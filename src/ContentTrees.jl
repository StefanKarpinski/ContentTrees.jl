module ContentTrees

export extract_tree

import Logging
import Pkg.TOML
import Random: randstring
import SHA
import Tar

## main API functions ##

function extract_tree(
    tarball::AbstractString,
    hash::AbstractString,
    root::AbstractString,
)
    temp, can_symlink = temp_path(root)

    # extract tarball, recording contents & symlinks
    types = Dict{String,String}()
    symlinks = Dict{String,String}()
    open(`gzcat $tarball`) do io
        Tar.extract(io, temp) do hdr
            executable = hdr.type == :file && (hdr.mode & 0o100) != 0
            types[hdr.path] = executable ? "executable" : string(hdr.type)
            if hdr.type == :symlink
                symlinks[hdr.path] = hdr.link
                return can_symlink
            else
                delete!(symlinks, hdr.path)
                return true
            end
        end
    end

    # populate types with all directories
    for path in keys(types)
        while (m = match(r"^(.*[^/])/+[^/]$", path)) !== nothing
            path = String(m.captures[1])
            types[path] = :directory
        end
    end

    # make copies instead of symlinks on filesystems that can't symlink
    if !can_symlink
        for (tar_path, link) in symlinks
            sys_path = joinpath(root, tar_path)
            target = joinpath(dirname(sys_path), link)
            if is_tree_path(root, target) && ispath(target)
                cp(target, sys_path)
            end
        end
    end

    # construct tree_info data structure
    tree_info_file = joinpath(temp, ".tree_info.toml")
    tree_info = Dict{String,Any}("git-tree-sha1" => hash)
    !isempty(types) && (tree_info["contents"] = types)
    !isempty(symlinks) && (tree_info["symlinks"] = symlinks)

    # if tree_info path exists, save its git hash
    if haskey(types, ".tree_info.toml")
        tree_info["hashes"] =
            Dict(".tree_info.toml" => git_hash(tree_info_file))
    end

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
    hash′ = git_hash(temp)
    if hash′ != hash
        msg  = "Tree hash mismatch!\n"
        msg *= "  Expected SHA1: $hash\n"
        msg *= "  Computed SHA1: $hash′"
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
    root::String
    hash::String
    types::Dict{String,Symbol}
    hashes::Dict{String,String}
    symlinks::Dict{String,String}
end

function TreeInfo(root::AbstractString)
    file = joinpath(root, ".tree_info.toml")
    isdir(root) ||
        error("no directory found at $root")
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
    if haskey(data, "contents")
        data["contents"] isa Dict{<:AbstractString,Any} ||
            error("[types] must be a TOML table in $file")
        for (path, type) in data["contents"]
            type in ("symlink", "directory", "executable", "file") ||
                error("invalid type $(repr(type)) for $(repr(path)) in $file")
            types[path] = Symbol(type)
        end
    end

    # ensure that all directories are included
    for path in keys(types)
        leaf = path
        while (m = match(r"^(.*[^/])/+[^/]$", path)) !== nothing
            path = m.captures[1]
            haskey(types, path) ||
                error("[types] missing $(repr(path)) containing $(repr(leaf))")
            types[path] == :directory ||
                error("[types] non-directory $(repr(path)) containing $(repr(leaf))")
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

    # check `.tree_info.toml` in types => `.tree_info.toml` in hashes
    if ".tree_info.toml" ∈ keys(types) && ".tree_info.toml" ∉ keys(hashes)
        error("missing hash for overwritten `.tree_info.toml` in $file")
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
        type == :symlink && path ∉ keys(symlinks) &&
            error("missing [symlinks] entry $(repr(path)) in $file")
    end

    # entries in symlinks must have type symlink
    for path in keys(symlinks)
        haskey(types, path) ||
            error("missing [types] entry for symlink $(repr(path)) in $file")
        (type = types[path]) == :symlink ||
            error("$(repr(path)) must have type symlink, not $type in $file")
    end

    return TreeInfo(root, hash, types, hashes, symlinks)
end

## git hashing ##

function git_hash(path::AbstractString; HashType::DataType = SHA.SHA1_CTX)
    stat = lstat(path)
    islink(stat) && return git_link_hash(path; HashType)
    isfile(stat) && return git_file_hash(path; HashType)
    isdir(stat)  && return git_tree_hash(path; HashType)
    error("unsupported file type for git hashing: $path")
end

function git_link_hash(path::AbstractString; HashType::DataType = SHA.SHA1_CTX)
    return git_object_hash("blob"; HashType) do io
        write(io, readlink(path))
    end
end

function git_file_hash(path::AbstractString; HashType::DataType = SHA.SHA1_CTX)
    return git_object_hash("blob"; HashType) do io
        write(io, read(path)) # TODO: more efficient sendfile
    end
end

git_tree_hash(path::AbstractString; HashType::DataType = SHA.SHA1_CTX) =
    git_tree_hash(TreeInfo(path), path; HashType)

function path_type(path::AbstractString)
    stat = lstat(path)
    ispath(stat) || return :absent
    islink(stat) && return :symlink
     isdir(stat) && return :directory
    isexec(stat) && return :executable
    isfile(stat) && return :file
    error("unexpected file type: $path")
end

const REPLACEMENT_TYPES = Dict(
    :directory  => Symbol[],
    :executable => [:file],
    :file       => [:executable],
    :symlink    => [:directory, :executable, :file],
)

function git_tree_hash(
    tree_info::TreeInfo,
    sys_path::AbstractString,
    tar_path::AbstractString = "";
    HashType::DataType = SHA.SHA1_CTX,
)
    entries = Tuple{String,Symbol,String}[]
    for name in readdir(sys_path, sort=false)
        let sys_path = joinpath(sys_path, name),
            tar_path = isempty(tar_path) ? name : "$tar_path/$name"

            # classify tarball and system types
            tar_type = get(tree_info.types, tar_path, :absent)
            tar_type == :absent && continue

            # handle the `.tree_info.toml` file
            if tar_path == ".tree_info.toml"
                hash = tree_info.hashes[tar_path]
            else
                sys_type = path_type(sys_path)

                function hash_path(sys_type, sys_path, tar_path)
                    if sys_type == :directory
                        git_tree_hash(tree_info, sys_path, tar_path; HashType)
                    elseif sys_type == :symlink
                        git_link_hash(sys_path; HashType)
                    else
                        git_file_hash(sys_path; HashType)
                    end
                end
                hash = hash_path(sys_type, sys_path, tar_path)

                # only some sys_types are acceptable replacements
                if sys_type ≠ tar_type && sys_type ∉ REPLACEMENT_TYPES[tar_type]
                    tar_type = sys_type # will cause a hash mismatch
                elseif tar_type == :symlink && sys_type != :symlink
                    # a symlink may be replaced by a copy of the target
                    tar_target = tree_info.symlinks[tar_path]
                    sys_target = joinpath(dirname(sys_path), tar_target)
                    if is_tree_path(root, sys_target)
                        sys_target_type = path_type(sys_target)
                        if sys_target_type != :absent
                            hash′ = hash_path(sys_target, sys_target_type, tar_target)
                        end
                    else
                        hash′ = nothing
                    end
                    # check that contents of sys_path and sys_target match
                    if hash == hash′
                        # if so, hash it as if it were a symlink to tar_target
                        hash = git_object_hash("blob"; HashType) do io
                            write(io, tar_target)
                        end
                    else
                        tar_type = sys_type # will cause a hash mismatch
                    end
                end
            end
            push!(entries, (name, tar_type, hash))
        end
    end

    # sort entries the same way git does
    by((name, type, hash)) = type == :directory ? "$name/" : name
    sort!(entries; by)

    return git_object_hash("tree"; HashType) do io
        for (name, type, hash) in entries
            mode = type == :directory  ?  "40000" :
                   type == :executable ? "100755" :
                   type == :file       ? "100644" :
                   type == :symlink    ? "120000" : @assert false
            print(io, mode, ' ', name, '\0', hash)
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

const EMPTY_HASHES = IdDict{DataType,String}()

function empty_hash(tree_info::TreeInfo, HashType::DataType)
    get!(EMPTY_HASHES, HashTypes) do
        empty_tree = mktempdir()
        hash = git_tree_hash(tree_info, empty_tree; HashType)
        rm(empty_tree)
        return hash
    end
end

## helper functions ##

isexec(stat::Base.Filesystem.StatStruct) = (filemode(stat) & 0o100) ≠ 0

is_tree_path(root::AbstractString, path::AbstractString) =
    startswith(normpath(path), normpath(root))

function temp_path(path::AbstractString)
    temp = "$path.$(randstring(8)).tmp"
    mkdir(temp)
    Base.Filesystem.temp_cleanup_later(temp)
    link_path = joinpath(temp, "link")
    loglevel = Logging.min_enabled_level(Logging.current_logger())
    can_symlink = try
        Logging.disable_logging(Logging.Warn)
        symlink("target", link_path)
        true
    catch err
        err isa Base.IOError || rethrow()
        false
    finally
        Logging.disable_logging(loglevel-1)
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
