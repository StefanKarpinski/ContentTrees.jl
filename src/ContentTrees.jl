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
    paths = Dict{String,Dict{Symbol,String}}()
    open(`gzcat $tarball`) do io
        Tar.extract(io, temp) do hdr
            is_valid_tar_path(hdr.path) ||
                error("invalid tarball path: $(repr(hdr.path))")
            executable = hdr.type == :file && (hdr.mode & 0o100) != 0
            info = Dict(:type => executable ? "executable" : string(hdr.type))
            if hdr.type == :symlink
                info[:link] = hdr.link
            end
            paths[hdr.path] = info
            return hdr.type ≠ :symlink || can_symlink
        end
    end

    # make copies instead of symlinks on filesystems that can't symlink
    if !can_symlink
        for (tar_path, info) in paths
            paths[:type] == :symlink || continue
            sys_path = joinpath(root, tar_path)
            target = joinpath(dirname(sys_path), link)
            if is_tree_path(root, target) && ispath(target)
                cp(target, sys_path) # TODO: what about circularity?
            end
        end
    end

    # populate all directories
    paths["."] = Dict(:type => "directory", :hash => hash)
    for path in keys(paths)
        while (m = match(r"^(.*[^/])/+[^/]+$", path)) !== nothing
            path = String(m.captures[1])
            path in keys(paths) || continue
            paths[path] = Dict(:type => "directory")
        end
    end

    # if tree_info path exists, save its git hash
    tree_info_file = joinpath(temp, ".tree_info.toml")
    if haskey(paths, ".tree_info.toml")
        paths[".tree_info.toml"][:hash] = git_hash(tree_info_file)
        @warn "overwriting extracted `.tree_info.toml`" path=tree_info_file
        rm(tree_info_file, recursive=true)
    end

    # write the tree_info file
    open(tree_info_file, write=true) do io
        TOML.print(io, sorted=true, paths)
    end

    # verify the tree
    hash′ = git_hash(temp)
    if hash′ != hash
        msg  = "Tree hash mismatch!\n"
        msg *= "  Expected SHA1: $hash\n"
        msg *= "  Computed SHA1: $hash′"
        # rm(temp, recursive=true)
        error(msg)
    end

    # move temp dir to right place
    ispath(root) && @warn "path already exists, replacing" path=root
    mv(temp, root, force=true)
    return
end

## type for representing `.tree_info.toml` data ##

mutable struct PathInfo
    type::Symbol
    link::String
    hash::String
    PathInfo(type::Union{Symbol,AbstractString}) = new(Symbol(type))
end

function tree_info(root::AbstractString)
    file = joinpath(root, ".tree_info.toml")
    isdir(root) ||
        error("no directory found at $root")
    ispath(file) ||
        error("no tree info file found at $file")
    data = TOML.parsefile(file)

    # extract and validate the git tree hash
    haskey(data, ".") ||
        error("missing root entry in $file")

    # extract and validiate path entries
    paths = Dict{String,PathInfo}()
    for (path, info) in data
        # validate the path itself
        is_valid_tar_path(path) ||
            error("contains invalid path: $(repr(path)) in $file")
        # get the path type
        haskey(info, "type") ||
            error("missing `type` field for $path in $file")
        type = info["type"]
        type in ("symlink", "directory", "executable", "file") ||
            error("invalid `type` field, $(repr(type)), for $path in $file")
        type = Symbol(type)
        path_info = PathInfo(type)
        # ensure link field iff symlink
        if type == :symlink
            haskey(info, "link") ||
                error("missing `link` field for symlink $path in $file")
            link = info["link"]
            link isa AbstractString ||
                error("invalid `link` field, $(repr(link)), for $path in $file")
            path_info.link = link
        else
            haskey(info, "link") &&
                error("`link` field present for non-symlink $path in $file")
        end
        # validate hash field if there is one
        if haskey(info, "hash")
            hash = info["hash"]
            hash isa AbstractString ||
                error("invalid `hash` value, $(repr(hash)), for $path in $file")
            hash = try normalize_hash(hash)
            catch err
                err isa ArgumentError || rethrow()
                error("invalid `hash`, $(repr(hash)), for $path in $file:\n$(err.msg)")
            end
            path_info.hash = hash
        end            
        # `.tree_info.toml` must have a hash
        if path == ".tree_info.toml"
            isdefined(path_info, :hash) ||
                error("missing required hash value for $path in $file")
        end
    end

    # ensure that all directories are included
    for path in keys(paths)
        leaf = path
        while (m = match(r"^(.*[^/])/+[^/]+$", path)) !== nothing
            path = String(m.captures[1])
            path in keys(paths) ||
                error("missing entry for directory $(repr(path)) in $file")
            paths[path].type == :directory ||
                error("path $path not a directory but contains $(repr(leaf)) in $file")
        end
    end

    return paths
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
    git_tree_hash(tree_info(path), path; HashType)

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
    paths::Dict{String,PathInfo},
    sys_path::AbstractString,
    tar_path::AbstractString = "";
    HashType::DataType = SHA.SHA1_CTX,
)
    entries = Tuple{Symbol,String,String}[]
    for name in readdir(sys_path, sort=false)
        let sys_path = joinpath(sys_path, name),
            tar_path = isempty(tar_path) ? name : "$tar_path/$name"

            # classify tarball and system types
            tar_path in keys(paths) || continue
            path_info = paths[tar_path]
            tar_type = path_info.type

            # handle the `.tree_info.toml` file
            if tar_path == ".tree_info.toml"
                hash = path_info.hash
            else
                sys_type = path_type(sys_path)

                # compute the hash of the system path
                function hash_path(sys_type, sys_path, tar_path)
                    if sys_type == :directory
                        git_tree_hash(paths, sys_path, tar_path; HashType)
                    elseif sys_type == :symlink
                        git_link_hash(sys_path; HashType)
                    else
                        git_file_hash(sys_path; HashType)
                    end
                end
                hash = hash_path(sys_type, sys_path, tar_path)

                # empty subtrees don't contribute to the git hash
                tar_type == :directory && hash == empty_tree(HashType) && continue

                # only some sys_types are acceptable replacements
                if sys_type ≠ tar_type && sys_type ∉ REPLACEMENT_TYPES[tar_type]
                    tar_type = sys_type # will cause a hash mismatch
                elseif tar_type == :symlink && sys_type != :symlink
                    # a symlink may be replaced by a copy of the target
                    target = joinpath(dirname(sys_path), path_info.link)
                    if is_tree_path(root, target)
                        target_type = path_type(target)
                        if target_type != :absent
                            hash′ = hash_path(target, target_type, path_info.link)
                        end
                    else
                        hash′ = nothing
                    end
                    # check that contents of sys_path and target match
                    if hash == hash′
                        # if so, hash it as if it were the expected symlink
                        hash = git_object_hash("blob"; HashType) do io
                            write(io, path_info.link)
                        end
                    else
                        tar_type = sys_type # will cause a hash mismatch
                    end
                end
            end
            push!(entries, (tar_type, hash, name))
        end
    end

    # sort entries the same way git does
    by((type, hash, name)) = type == :directory ? "$name/" : name
    sort!(entries; by)

    return git_object_hash("tree"; HashType) do io
        for (type, hash, name) in entries
            mode = type == :directory  ?  "40000" :
                   type == :executable ? "100755" :
                   type == :file       ? "100644" :
                   type == :symlink    ? "120000" : @assert false
            print(io, mode, ' ', name, '\0')
            write(io, hex2bytes(hash))
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

function empty_hash(HashType::DataType)
    get!(EMPTY_HASHES, HashTypes) do
        empty_tree = mktempdir()
        hash = git_tree_hash(Dict{String,PathInfo}(), empty_tree; HashType)
        rm(empty_tree)
        return hash
    end
end

## helper functions ##

isexec(stat::Base.Filesystem.StatStruct) = (filemode(stat) & 0o100) ≠ 0

is_tree_path(root::AbstractString, path::AbstractString) =
    startswith(normpath(path), normpath(root))

function is_valid_tar_path(path::AbstractString)
    path == "." && return true
    isempty(path) && return false
    parts = split(path, '/')
    isempty(parts[end]) && pop!(parts)
    for part in parts
        part in ("", ".", "..") && return false
    end
    return true
end

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
