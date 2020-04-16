using Test
using ContentTrees

temp = mktempdir()
hash = "b6ab99a8891d69c3bef8018ded1b3f4ed0bd45b4"
extract_tree("test/test_tarball.tar.gz", hash, temp)
rm(temp, recursive=true)
