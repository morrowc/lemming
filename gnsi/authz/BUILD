load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "authz",
    srcs = ["authz.go"],
    importpath = "github.com/openconfig/lemming/gnsi/authz",
    visibility = ["//visibility:public"],
    deps = [
        "//gnsi/acltrie",
        "@com_github_openconfig_gnmi//proto/gnmi",
        "@com_github_openconfig_gnsi//pathz",
        "@org_golang_google_grpc//codes",
        "@org_golang_google_grpc//status",
    ],
)

