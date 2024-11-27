load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "tlsutils",
    srcs = ["tlsutils.go"],
    importpath = "github.com/openconfig/lemming/gnsi/tlsutils",
    visibility = ["//visibility:public"],
    deps = [
        "@com_github_openconfig_gnsi//certz",
    ],
)


go_test(
    name = "tlsutils_test",
    srcs = [
        "tlsutils_test.go",
    ],
    deps = [
        "@com_github_google_go_cmp//cmp",
        "@com_github_openconfig_gnsi//certz",
    ],
)
