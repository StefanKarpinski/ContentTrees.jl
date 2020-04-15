module ContentTrees

export
    check_tree,
    verify_tree,
    extract_tree

import Logging
import Pkg.TOML
import Random: randstring
import SHA
import Tar

## main API functions ##

function check_tree(
    root::AbstractString,
    hash::AbstractString,
)
    file = joinpath(root, ".tree_info.toml")
    if !isfile(file)
        @error "not a content tree" root
        return false
    end
    tree_info = try
        TOML.parsefile(file)
    catch err
        @error "invalid TOML file" file err
        return false
    end
    tree_hash = get(tree_info, "git-tree-sha1"), nothing)
    if tree_hash === nothing
        @error "no `git-tree-sha1` entry" file
        return false
    end
    hash = normalize_hash(hash)
    tree_hash = normalize_hash(tree_hash)
    return hash == tree_hash
end

function fsck_tree(root::AbstractString)
    # check contents, fixup if possible, otherwise fail
end

function extract_tree(
    root::AbstractString,
    hash::AbstractString,
    tarball::AbstractString,
)
    temp, can_symlink = temp_path(root)
    # extract tarball, recording contents & symlinks
    types = Dict{String,String}()
    symlinks = Dict{String,String}()
    open(`gzcat $tarball`) do io
        Tar.extract(io, temp) do hdr
            executable = hdr.type == :file && (hdr.mode & 0o100) != 0
            contents[hdr.path] = executable ? "executable" : string(hdr.type)
            if hdr.type == :symlink
                symlinks[hdr.path] = hdr.link
                return can_symlink
            else
                delete!(symlinks, hdr.path)
                return true
            end
        end
    end
    # make copies instead of symlinks on filesystems that can't symlink
    if !can_symlink
        for (tar_path, link) in symlinks
            sys_path = joinpath(root, tar_path)
            target = joinpath(dirname(sys_path), link)
            # TODO: refuse to copy target outside of tree
            ispath(target) && cp(target, path)
        end
    end
    # construct tree_info data structure
    tree_info_file = joinpath(temp, ".tree_info.toml")
    tree_info = Dict{String,Any}("git-tree-sha1" => hash)
    !isempty(types) && (tree_info["types"] = types)
    !isempty(symlinks) && (tree_info["symlinks"] = symlinks)
    # if tree_info path exists, save its git hash
    haskey(types, ".tree_info.toml") && tree_info["hashes"] =
        Dict(".tree_info.toml" => git_hash(tree_info_file))
    # write the tree_info file
    if ispath(tree_info_file)
        @assert haskey(tree_info["hashes"], ".tree_info.toml")
        @warn "overwriting extracted `.tree_info.toml`" path=tree_info_file
        rm(tree_info_file, recursive=true)
    end
    open(tree_info_file, write=true) do io
        TOML.print(io, sorted=true, tree_info)
    end
    # verify the tree
    calc_hash = git_tree_hash(temp)
    if calc_hash != tree_hash
        msg  = "Tree hash mismatch!\n"
        msg *= "  Expected SHA1: $tree_hash\n"
        msg *= "  Computed SHA1: $calc_hash"
        rm(temp, recursive=true)
        error(msg)
    end
    # move temp dir to right place
    ispath(root) && @warn "path already exists, replacing" path=root
    mv(temp, root, force=true)
    return
end

## type for representing `.tree_info.toml` data ##

struct TreeInfo
    path::String
    hash::String
    types::Dict{String,Symbol}
    hashes::Dict{String,String}
    symlinks::Dict{String,String}
end

function TreeInfo(file::AbstractString)
    ispath(file) ||
        error("no tree info found at $file")
    data = TOML.parsefile(file)

    # extract and validate the git tree hash
    haskey(data, "git-tree-sha1") ||
        error("git-tree-sha1 missing in $file")
    hash = data["git-tree-sha1"]
    hash isa AbstractString ||
        error("git-tree-sha1 must be a string in $file")
    hash = try normalize_hash(hash)
    catch err
        err isa ArgumentError || rethrow()
        error("invalid git-tree-sha1 value in $file:\n$(err.msg)")
    end

    # extract and validate types dict
    types = Dict{String,Symbol}()
    if haskey(data, "types")
        data["types"] isa Dict{<:AbstractString,Any} ||
            error("[types] must be a TOML table in $file")
        for (path, type) in data["types"]
            type in ("symlink", "directory", "executable", "file") ||
                error("invalid type $(repr(type)) for $(repr(path)) in $file"))
            types[path] = Symbol(type)
        end
    end

    # extract and validate hashes dict
    hashes = Dict{String,String}()
    if haskey(data, "hashes")
        data["hashes"] isa Dict{<:AbstractString,Any} ||
            error("[hashes] must be a TOML table in $file")
        for (path, hash) in data["hashes"]
            hash = try normalize_hash(hash)
            catch err
                err isa ArgumentError || rethrow()
                error("invalid SHA1 hash for $(repr(path)) in $file:\n$(err.msg)")
            end
            hashes[path] = hash
        end
    end

    # extract and validate symlinks dict
    symlinks = Dict{String,String}()
    if haskey(data, "symlinks")
        data["symlinks"] isa Dict{<:AbstractString,Any} ||
            error("[symlinks] must be a TOML table in $file")
        for (path, link) in data["symlinks"]
            symlinks[path] = link
        end
    end

    # symlink type paths must have symlinks entries
    for (path, type) in types
        haskey(symlinks, path) ||
            error("missing [symlinks] entry $(repr(path)) in $file")
    end

    # entries in symlinks must have type symlink
    for path in keys(symlinks)
        haskey(types, path) ||
            error("missing [types] entry $(repr(path)) in $file")
        (type = types[path]) == :symlink ||
            error("$(repr(path)) must have type symlink, not $type in $file")
    end

    return TreeInfo(file, hash, types, hashes, symlinks)
end

## git hashing ##

git_hash(path::AbstractString) =
    (isdir(path) ? git_tree_hash : git_blob_hash)(path)

function git_tree_hash(root::AbstractString; HashType::DataType = SHA.SHA1_CTX)
    tree_info = TreeInfo(joinpath(root, ".tree_info.toml"))
    return git_subtree_hash(tree_info, root; HashType)
end

function git_subtree_hash(
    tree_info::TreeInfo,
    sys_path::AbstractString,
    tar_path::AbstractString = "";
    HashType::DataType = SHA.SHA1_CTX,
)
    entries = Tuple{String,String,Int}[]
    for name in readdir(sys_path, sort=false)
        let tar_path = isempty(tar_path) ? name : "$tar_path/$name",
            sys_path = joinpath(sys_path, name)

            # classify system and tarball types
            tar_type = get(tree_info.types, tar_path, :absent)
            stat = lstat(sys_path)
            sys_type = islink(stat) ? :symlink    :
                        isdir(stat) ? :directory  :
                       isexec(stat) ? :executable :
                       ispath(stat) ? :file       :
                                      :absent
            sys_type ∈ (allowed = ALLOWED_SYS_TYPES[tar_type]) ||
                error("path $sys_path is $sys_type, should be $(allowed[1])")

            # handle path based on types
            tar_type == :absent && continue
            if tar_type == :symlink
                link = tree_info.symlinks[tar_path]
                if sys_type == :absent
                    link ∉ keys(tree_info.types) ||
                        error("")
                else

                end
            end

            if isdir(stat)
                hash = git_tree_hash(path; HashType, tree_info)
                hash == empty_hash(HashType) && continue
            else
                if skip_tree_info && name == ".tree_info.toml"
                    info = TOML.parsefile(path)
                    haskey(info,"git-path-sha1s") &&
                    haskey(info["git-path-sha1s"],name) || continue
                    hash = info["git-path-sha1s"][name] :: AbstractString
                else
                    hash = git_blob_hash(path; HashType)
                end
            end
            push!(entries, (name, hash, mode))
        end
    end
    by((name, hash, mode)) = mode == 0o040000 ? "$name/" : name
    sort!(entries; by)

    return git_object_hash("tree"; HashType) do out
        for (name, hash, mode) in entries
            print(out, string(UInt32(mode), base=8))
            print(out, ' ', name, '\0', hash)
        end
    end
end

function git_blob_hash(path::AbstractString; HashType = SHA.SHA1_CTX)
    return git_object_hash("blob"; HashType) do out
        if islink(path)
            write(out, readlink(path))
        else
            write(out, read(path)) # TODO: more efficient sendfile
        end
    end
end

function git_object_hash(emit::Function, kind::AbstractString; HashType::DataType)
    ctx = HashType()
    body = codeunits(sprint(emit))
    SHA.update!(ctx, codeunits("$kind $(length(body))\0"))
    SHA.update!(ctx, body)
    return bytes2hex(SHA.digest!(ctx))
end

const ALLOWED_SYS_TYPES = Dict(
    :absent     => (:symlink, :directory, :executable, :file, :absent),
    :directory  => (:directory,),
    :executable => (:executable, :file),
    :file       => (:file, :executable),
    :symlink    => (:symlink, :directory, :executable, :file, :absent),
)

isexec(stat::Base.Filesystem.StatStruct) = filemode(stat) & 0o100

const EMPTY_HASHES = IdDict{DataType,String}()

function empty_hash(HashType::DataType)
    get!(EMPTY_HASHES, HashTypes) do
        empty_tree = mktempdir()
        hash = git_subtree_hash(empty_tree; HashType)
        rm(empty_tree)
        return hash
    end
end

## helper functions ##

function temp_path(path::AbstractString)
    temp = "$path.$(randstring(8)).tmp"
    mkdir(temp)
    Base.Filesystem.temp_cleanup_later(temp)
    link_path = joinpath(temp, "link")
    loglevel = Logging.min_enabled_level(current_logger())
    can_symlink = try
        disable_logging(Logging.Warn)
        symlink("target", link_path)
        true
    catch err
        err isa Base.IOError || rethrow()
        false
    finally
        disable_logging(loglevel-1)
        rm(link_path; force=true)
    end
    return temp, can_symlink
end

function normalize_hash(hash::AbstractString, bits::Integer=160)
    bits % 16 == 0 ||
        throw(ArgumentError("Invalid number of bits for a hash: $bits"))
    len = bits >> 2
    len_ok = length(hash) == len
    chars_ok = occursin(r"^[0-9a-f]*$"i, hash)
    if !len_ok || !chars_ok
        msg = "Hash value must be $len hexadecimal characters ($bits bits); "
        msg *= "Given hash value "
        if !chars_ok
            if isascii(hash)
                msg *= "contains non-hexadecimal characters"
            else
                msg *= "is non-ASCII"
            end
        end
        if !chars_ok && !len_ok
            msg *= " and "
        end
        if !len_ok
            msg *= "has the wrong length ($(length(hash)))"
        end
        msg *= ": $(repr(hash))"
        throw(ArgumentError(msg))
    end
    return lowercase(hash)
end

end # module
