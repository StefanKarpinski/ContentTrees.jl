module ContentTrees

export extract_tree

import Logging
import Pkg.TOML
import Random: randstring
import SHA
import Tar

## main API functions ##

mutable struct PathNode
    type::Symbol
    hash::String
    link::String
    copy::Union{PathNode,Nothing}
    parent::PathNode
    children::Dict{String,PathNode}
    function PathNode(type::Symbol)
        node = new(type)
        if type == :directory
            node.children = Dict{String,PathNode}()
        end
        return node
    end
end

function PathNode(type::Symbol, parent::PathNode)
    node = PathNode(type)
    node.parent = parent
    return node
end

# only for debugging, but quite useful
function Base.show(io::IO, node::PathNode)
    print(io, "PathNode(")
    show(io, node.type)
    for field in (:hash, :link)
        if isdefined(node, field)
            print(io, ", $field = ")
            show(io, getfield(node, field))
        end
    end
    if isdefined(node, :children)
        print(io, ", children = {")
        for (i, (name, child)) in enumerate(node.children)
            i == 1 || print(io, ", ")
            show(io, name)
            print(io, " = ")
            show(io, child)
        end
        print(io, "}")
    end
    print(io, ")")
end

# find a node in the tree, creating nodes as necessary
function path_node!(tree::PathNode, path::AbstractString, type::Symbol)
    node = tree
    parts = split_tar_path(path)
    for (i, name) in enumerate(parts)
        if node.type ≠ :directory
            here = join(parts[1:i-1], '/')
            error("non-directory $(repr(here)) has contents: $(repr(path))")
        end
        if i < length(parts)
            node = get!(node.children, name) do
                PathNode(:directory, node)
            end
        else
            # overwrite whatever is already there
            node = node.children[name] = PathNode(type, node)
        end
    end
    return node
end

function resolve_symlinks!(node::PathNode)
    if node.type == :symlink
        node.copy = symlink_target(node.parent, node.link)
    elseif node.type == :directory
        foreach(resolve_symlinks!, values(node.children))
    end
    if !isdefined(node, :parent)
        follow_symlinks!(node::PathNode)
    end
end

function follow_symlinks!(node::PathNode)
    if node.type == :symlink && node.copy !== nothing
        node.copy = follow_symlinks(node.copy, [node])
        if node.copy !== nothing && isanscestor(node.copy, node)
            node.copy = nothing
        end
    elseif node.type == :directory
        foreach(follow_symlinks!, values(node.children))
    end
end

function copy_symlinks(root::AbstractString, node::PathNode)
    if node.type == :symlink
        link = node_path(root, node)
        if node.copy === nothing
            @warn("skipping copy of broken, circular or external symlink",
                path=link, link=node.link)
        else
            cp(node_path(root, node.copy), link)
        end
    elseif node.type == :directory
        for child in values(node.children)
            copy_symlinks(root, child)
        end
    end
end

symlink_target(node::PathNode, path::AbstractString) =
    startswith(path, '/') ? nothing : symlink_target(node, split(path, r"/+"))

function symlink_target(node::PathNode, parts::Vector{<:AbstractString}, i::Int=1)
    if i > length(parts)
        node
    elseif parts[i] in ("", ".")
        if node.type == :directory
            symlink_target(node, parts, i+1)
        end
    elseif parts[i] == ".."
       if node.type == :directory && isdefined(node, :parent)
            symlink_target(node.parent, parts, i+1)
        end
    elseif node.type == :directory
        child = get(node.children, parts[i], nothing)
        if child !== nothing
            symlink_target(child, parts, i+1)
        end
    end
end

function follow_symlinks(node::PathNode, seen::Vector{PathNode})
    node.type != :symlink && return node
    (node ∈ seen || node.copy === nothing) && return nothing
    return follow_symlinks(node.copy, push!(seen, node))
end

function node_path(root::AbstractString, node::PathNode)
    isdefined(node, :parent) || return root
    for (name, sibling) in node.parent.children
        sibling === node || continue
        return joinpath(node_path(root, node.parent), name)
    end
    error("internal error: node doesn't appear in parent's children")
end

isanscestor(a::PathNode, b::PathNode) =
    a === b || isdefined(b, :parent) && isanscestor(a, b.parent)

const METADATA_KEYS = split("type link target hash")

name_to_key(name::AbstractString)::String =
    name in METADATA_KEYS ? "./$name" : name
key_to_name(key::AbstractString)::String =
    startswith("./") ? chop(key, head=2, tail=0) : key

function to_toml(node::PathNode)
    dict = Dict{String,Any}()
    if node.type == :directory
        isdefined(node, :parent) || (dict["hash"] = node.hash)
        isempty(node.children) && (dict["type"] = node.type)
        for (name, child) in node.children
            dict[name_to_key(name)] = to_toml(child)
        end
    else
        dict["type"] = node.type
        if node.type == :symlink
            dict["link"] = node.link
            if node.copy !== nothing
                dict["copy"] = node.copy.hash
            end
        else
            dict["hash"] = node.hash
        end
    end
    return dict
end

function extract_tree(
    tarball::AbstractString,
    root::AbstractString,
    hash::Union{AbstractString, Nothing} = nothing;
    HashType::DataType = SHA.SHA1_CTX,
)
    # remove destination first if it exists
    ispath(root) && @warn "path already exists, replacing" path=root

    # create tree info structure
    tree = PathNode(:directory)
    temp, can_symlink = temp_path(root)

    # extract tarball, recording contents
    open(`gzcat $tarball`) do io
        Tar.extract(io, temp) do hdr
            executable = hdr.type == :file && (hdr.mode & 0o100) != 0
            node = path_node!(tree, hdr.path, executable ? :executable : hdr.type)
            hdr.type == :symlink && (node.link = hdr.link)
            hdr.type != :symlink || can_symlink
        end
    end
    resolve_symlinks!(tree)
    compute_hashes!(temp, tree; HashType)

    # make copies instead of symlinks on filesystems that can't symlink
    !can_symlink && copy_symlinks(temp, tree)

    # verify the tree has the expected hash
    if hash !== nothing && tree.hash != hash
        msg  = "Tree hash mismatch!\n"
        msg *= "  Expected: $hash\n"
        msg *= "  Computed: $(tree.hash)"
        # rm(temp, recursive=true) # TODO: uncomment
        error(msg)
    end

    # if tree_info path exists, remove it
    tree_info_file = joinpath(temp, ".tree_info.toml")
    if haskey(tree.children, ".tree_info.toml")
        @warn "overwriting extracted `.tree_info.toml`" path=tree_info_file
        rm(tree_info_file, recursive=true)
    end

    # construct & write tree_info to file
    tree_info = to_toml(tree)
    open(tree_info_file, write=true) do io
        TOML.print(io, sorted=true, tree_info)
    end

    # move temp dir to right place
    mv(temp, root, force=true)
    return
end

## type for representing `.tree_info.toml` data ##

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
        # TODO: validate path (check non-empty, no '/' and not '.' or '..')
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

## computing the hashes ##

function compute_hashes!(
    path::AbstractString,
    node::PathNode;
    HashType::DataType = SHA.SHA1_CTX,
)
    if node.type == :directory
        nodes = Pair{String,PathNode}[
            name => child for (name, child) in node.children
        ]
        let by((name, child)) = child.type == :directory ? "$name/" : name
            sort!(nodes; by)
        end
        for (name, child) in nodes
            compute_hashes!(joinpath(path, name), child; HashType)
        end
        node.hash = git_object_hash("tree"; HashType) do io
            for (name, child) in nodes
                mode = child.type == :directory  ?  "40000" :
                       child.type == :executable ? "100755" :
                       child.type == :file       ? "100644" :
                       child.type == :symlink    ? "120000" : @assert false
                print(io, mode, ' ', name, '\0')
                write(io, hex2bytes(child.hash))
            end
        end
    elseif node.type == :symlink
        node.hash = git_object_hash("blob"; HashType) do io
            write(io, node.link)
        end
    else # file/executable
        node.hash = git_object_hash("blob"; HashType) do io
            write(io, read(path)) # TODO: more efficient sendfile
        end
    end
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
    paths::Dict{String,PathNode},
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

function split_tar_path(path::AbstractString)
    path == "." && return String[]
    isempty(path) &&
        error("invalid empty tar path")
    parts = split(path, r"/+")
    isempty(parts[end]) && pop!(parts)
    for part in parts
        part in (".", "..") &&
            error("invalid tar path contains $(repr(part)): $path")
    end
    return parts
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
