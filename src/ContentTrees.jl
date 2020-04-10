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

function verify_tree(
    root::AbstractString,
    hash::Union{AbstractString, Nothing} = nothing,
)
    # if hash === nothing, get from .tree_info.toml
end

function extract_tree(
    root::AbstractString,
    hash::AbstractString,
    tarball::AbstractString,
)
    temp, features = temp_path(root)
    # extract tarball, recording contents & symlinks
    contents = Dict{String,String}()
    symlinks = Dict{String,String}()
    open(`gzcat $tarball`) do io
        Tar.extract(io, temp) do hdr
            executable = hdr.type == :file && (hdr.mode & 0o100) != 0
            contents[hdr.path] = executable ? "executable" : string(hdr.type)
            if hdr.type == :symlink && !features["symlinks"]
                symlinks[hdr.path] = hdr.link
                return false
            else
                delete!(symlinks, hdr.path)
                return true
            end
        end
    end
    # make copies instead of symlinks on filesystems that can't symlink
    for (path, link) in symlinks
        target = joinpath(dirname(path), link)
        cp(target, path)
    end
    # construct tree_info data structure
    tree_info_file = joinpath(temp, ".tree_info.toml")
    tree_info = Dict{String,Any}(
        "git-tree-sha1" => hash,
        "features" => features,
    )
    !isempty(contents) && (tree_info["contents"] = contents)
    !isempty(symlinks) && (tree_info["symlinks"] = symlinks)
    # if tree_info path exists, save its git hash
    haskey(contents, ".tree_info.toml") && tree_info["git-path-sha1s"] =
        Dict(".tree_info.toml" => git_hash(tree_info_file))
    # write the tree_info file
    if ispath(tree_info_file)
        @assert haskey(tree_info["git-path-sha1s"], ".tree_info.toml")
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

## helper functions ##

function temp_path(path::AbstractString)
    temp = "$path.$(randstring(8)).tmp"
    mkdir(temp)
    Base.Filesystem.temp_cleanup_later(temp)
    features = Dict{String,Bool}()
    link_path = joinpath(temp, "link")
    loglevel = Logging.min_enabled_level(current_logger())
    features["symlinks"] = try
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
    file_path = joinpath(temp, "file")
    touch(file_path)
    chmod(file_path, 0o700)
    features["executables"] = filemode(file_path) & 0o100 == 0o100
    chmod(file_path, 0o600)
    features["non-executables"] = filemode(file_path) & 0o100 == 0o000
    rm(file_path)
    return temp, features
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

## git tree & file hashing ##

git_hash(path::AbstractString) =
    (isdir(path) ? git_tree_hash : git_blob_hash)(path)

function git_tree_hash(root::AbstractString; HashType::DataTypes = SHA.SHA1_CTX)
    if tree_info === nothing
        tree_info_file = joinpath(root, ".tree_info.toml")
        tree_info = isfile(joinpath(root, ".tree_info.toml")) ?
            TOML.parsefile(tree_info_file) : Dict{String,Any}()
    end
end

const EMPTY_HASHES = IdDict{DataType,String}()

function empty_hash(HashType::DataTypes)
    get!(EMPTY_HASHES, HashTypes) do
        empty_tree = mktempdir()
        hash = git_subtree_hash(empty_tree; HashType)
        rm(empty_tree)
        return hash
    end
end

const DEFAULT_FEATURES = Dict(
    "symlinks" => true,
    "executables" => true,
    "non-executables" => true,
)

isexec(stat::Base.Filesystem.StatStruct) = filemode(stat) & 0o100

function git_classify(
    tree_info::Dict{String,Any},
    sys_path::AbstractString,
    tar_path::AbstractString,
)
    # get the on-disk type of the path
    stat = lstat(sys_path)
    sys_type =
        islink(stat) ? :symlink    :
         isdir(stat) ? :directory  :
        isexec(stat) ? :executable :
                       :file

    # look path in contents section of file info
    haskey(tree_info, "contents") || return sys_type
    haskey(tree_info["contents"], tar_path) || return :ignore
    tar_type = tree_info["contents"]
    tar_type isa AbstractString ||
        error("invalid entry in tree_info for $(repr(tar_path)): $(repr(tar_type))")
    tar_type = Symbol(tar_type)
    tar_type == sys_type && return tar_type

    # handle missing features
    features = get(tree_info, "features", DEFAULT_FEATURES)
    tar_type == :symlink && sys_type != :symlink &&
        !get(features, "symlinks", true) && return tar_type
    tar_type == :executable && sys_type == :file &&
        !get(features, "executables", true) && return tar_type
    tar_type == :file && sys_type == :executable &&
        !get(features, "non-executables", true) && return tar_type

    # otherwise this is an invalid combination of types
    error("invalid tree/path types for $(repr(tar_path)): $tar_type/$sys_type")
end

function git_subtree_hash(
    sys_path::AbstractString,
    tar_path::AbstractString,
    tree_info::Dict{String,Any};
    HashType::DataTypes = SHA.SHA1_CTX,
)
    entries = Tuple{String,String,Int}[]
    for name in readdir(sys_path, sort=false)
        sys_path′ = joinpath(sys_path, name)
        tar_path′ = isempty(tar_path) ? name : "$tar_path/$name"
        mode = git_mode(sys_path′, tar_path′, tree_info)
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
    by((name, hash, mode)) = mode == 0o040000 ? "$name/" : name
    sort!(entries, by = by)

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

end # module
