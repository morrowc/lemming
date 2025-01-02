load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "store",
    srcs = ["store.go"],
    importpath = "github.com/openconfig/lemming/gnsi/store",
    visibility = ["//visibility:public"],
    deps = [
        "@com_github_openconfig_gnsi//certz",
        "@org_golang_google_grpc//codes",
        "@org_golang_google_grpc//status",
    ],
)
