module ContentTrees

export
    check_tree,
    verify_tree,
    extract_tree

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
    # extract tarball, recording contents & symlinks
    temp = temppath(root)
    contents = Dict{String,String}()
    symlinks = Dict{String,String}()
    open(`gzcat $tarball`) do io
        Tar.extract(io, temp) do hdr
            executable = hdr.type == :file && (hdr.mode & 0o100) != 0
            contents[hdr.path] = executable ? "executable" : string(hdr.type)
            hdr.type == :symlink && (symlinks[hdr.path] = hdr.link)
            return true # extract everything
        end
    end
    # construct tree_info data structure
    tree_info = Dict{String,Any}("git-tree-sha1" => hash)
    !isempty(contents) && (tree_info["contents"] = contents)
    !isempty(symlinks) && (tree_info["symlinks"] = symlinks)
    # if tree_info path exists, save its git hash
    if haskey(contents, ".tree_info.toml")
        hash_func = (isdir(tree_info) ? GitTools.tree_hash : GitTools.blob_hash)
        tree_info["git-path-sha1s"] = Dict(
            ".tree_info.toml" => bytes2hex(hash_func(tree_info))
        )
    end
    # write the tree_info file
    tree_info_file = joinpath(temp, ".tree_info.toml")
    if ispath(tree_info_file)
        @assert haskey(tree_info, "git-path-sha1s", ".tree_info.toml")
        @warn "overwriting extracted `.tree_info.toml`" path=tree_info
        rm(tree_info_file, recursive=true)
    end
    open(tree_info, write=true) do io
        TOML.print(io, sorted=true, tree_info)
    end
    # verify the tree
    calc_hash = hash_tree(temp)
    if tree_hash !== nothing && calc_hash != tree_hash
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

function temppath(path::AbstractString)
    temp = "$path.$(randstring(8)).tmp"
    Base.Filesystem.temp_cleanup_later(temp)
    return temp
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

## git tree hashing ##

const EMPTY_HASHES = IdDict{DataTypes,String}()

function empty_hash(HashType::DataTypes)
    get!(EMPTY_HASHES, HashTypes) do
        tree_hash(mktempdir(), HashType)
    end
end

isexec(stat::Base.Filesystem.StatStruct) = filemode(stat) & 0o100

function tree_hash(root::AbstractString, HashType::DataTypes = SHA.SHA1_CTX)
    entries = Tuple{String,String,Int}[]
    for name in readdir(root)
        name == ".git" && continue
        path = joinpath(root, name)
        stat = lstat(path)
        mode = islink(stat) ? 0o120000 :
                isdir(stat) ? 0o040000 :
               isexec(stat) ? 0o100755 : 0o100644
        if isdir(stat)
            hash = tree_hash(path)
            hash == empty_hash(HashType) && continue
        else
            hash = blob_hash(path)
        end
        push!(entries, (name, hash, mode))
    end

    # sort entries by name (with trailing slashes for directories)
    sort!(entries, by = ((name, hash, mode),) -> mode == 0o040000 ? "$name/" : name)

    # precompute the tree record size
    size = 0
    for (name, hash, mode) in entries
        size += ndigits(UInt32(mode); base=8) + ncodeunits(name) + 22
    end

    # return the hash of these entries
    ctx = HashType()
    SHA.update!(ctx, Vector{UInt8}("tree $size\0"))
    for (name, hash, mode) in entries
        SHA.update!(ctx, Vector{UInt8}("$mode $name\0"))
        SHA.update!(ctx, hash)
    end
    return SHA.digest!(ctx)
end

function blob_hash(path::AbstractString, HashType = SHA.SHA1_CTX)
    link = islink(path)
    target = link ? readlink(path) : nothing
    size = link ? length(target) : filesize(path)
    ctx = HashType()
    SHA.update!(ctx, Vector{UInt8}("blob $size\0"))
    if link
        update!(ctx, codeunits(target))
    else
        open(path, "r") do io
            buf = Vector{UInt8}(undef, 4096)
            while !eof(io)
                n = readbytes!(io, buf)
                update!(ctx, buf, n)
            end
        end
    end
    return SHA.digest!(ctx)
end

end # module
