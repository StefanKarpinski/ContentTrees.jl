using Test
using ContentTrees
using BSDiff
using Tar

extract_tree(
    "test/tree.tar.gz",
    "test/tree",
)

registry = expanduser("~/.julia/registries/General")
new_tarball = open(Tar.rewrite, `git -C $registry archive 'master@{now}'`)
old_tarball = open(Tar.rewrite,	`git -C $registry archive 'master@{1 week ago}'`)
patch_file = bsdiff(old_tarball, new_tarball)

old_root = tempname()
old_hash = extract_tree(old_tarball, old_root)

new_root = tempname()
