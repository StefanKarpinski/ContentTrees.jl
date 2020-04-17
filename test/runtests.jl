using Test
using ContentTrees

dir = mktempdir()
hash = "d6d4b8e929960406ef9176b2b30e6a484b0919f2"
extract_tree("test/tree.tar.gz", hash, dir)
@enter ContentTrees.git_hash(temp)
