use std::env;
use std::path::PathBuf;

fn build_hdcd() {
    let mut build = cc::Build::new();
    build.cpp(true);

    // 列出所有C++源文件
    let files = vec![
        "src/cffi/cmd.cpp",
        "src/cffi/getparameter.cpp",
        "src/cffi/log.cpp",
        // "src/cffi/mount.cpp",
        // "src/cffi/mount_wrapper.cpp",
        // "src/cffi/oh_usb.cpp",
        "src/cffi/sendmsg.cpp",
        "src/cffi/serial_struct.cpp",
        "src/cffi/sys_para.cpp",
        "src/cffi/transfer.cpp",
        // "src/cffi/uart.cpp",
        // "src/cffi/uart_wrapper.cpp",
        "src/cffi/usb_util.cpp",
        // "src/cffi/usb_wrapper.cpp",
        "src/cffi/utils.cpp",
        "bounds_checking_function/src/fscanf_s.c",
        "bounds_checking_function/src/fwscanf_s.c",
        "bounds_checking_function/src/gets_s.c",
        "bounds_checking_function/src/memcpy_s.c",
        "bounds_checking_function/src/memmove_s.c",
        "bounds_checking_function/src/memset_s.c",
        "bounds_checking_function/src/scanf_s.c",
        "bounds_checking_function/src/securecutil.c",
        "bounds_checking_function/src/secureinput_a.c",
        "bounds_checking_function/src/secureinput_w.c",
        "bounds_checking_function/src/secureprintoutput_a.c",
        "bounds_checking_function/src/secureprintoutput_w.c",
        "bounds_checking_function/src/snprintf_s.c",
        "bounds_checking_function/src/sprintf_s.c",
        "bounds_checking_function/src/sscanf_s.c",
        "bounds_checking_function/src/strcat_s.c",
        "bounds_checking_function/src/strcpy_s.c",
        "bounds_checking_function/src/strncat_s.c",
        "bounds_checking_function/src/strncpy_s.c",
        "bounds_checking_function/src/strtok_s.c",
        "bounds_checking_function/src/swprintf_s.c",
        "bounds_checking_function/src/swscanf_s.c",
        "bounds_checking_function/src/vfscanf_s.c",
        "bounds_checking_function/src/vfwscanf_s.c",
        "bounds_checking_function/src/vscanf_s.c",
        "bounds_checking_function/src/vsnprintf_s.c",
        "bounds_checking_function/src/vsprintf_s.c",
        "bounds_checking_function/src/vsscanf_s.c",
        "bounds_checking_function/src/vswprintf_s.c",
        "bounds_checking_function/src/vswscanf_s.c",
        "bounds_checking_function/src/vwscanf_s.c",
        "bounds_checking_function/src/wcscat_s.c",
        "bounds_checking_function/src/wcscpy_s.c",
        "bounds_checking_function/src/wcsncat_s.c",
        "bounds_checking_function/src/wcsncpy_s.c",
        "bounds_checking_function/src/wcstok_s.c",
        "bounds_checking_function/src/wmemcpy_s.c",
        "bounds_checking_function/src/wmemmove_s.c",
        "bounds_checking_function/src/wscanf_s.c",
        "src/dep.cpp"
    ];

    println!("cargo:rerun-if-changed={}", "src/dep.cpp");

    // 为每个文件添加一个.file()条目
    for file in files {
        build.file(file);
        // println!("cargo:rerun-if-changed={}", file2);
    }

    // 添加头文件搜索路径
    build.include("/Users/wetest/workplace/openharmoney/developtools_hdc_master/hdc_rust/bounds_checking_function/include")
    .include("/opt/homebrew/include/");
    // 指定使用C++17编译
    build.flag_if_supported("-std=c++17");

    // 根据目标操作系统设置不同的C++宏
    if cfg!(target_os = "macos") {  // windows linux
        build.define("HOST_MAC", "1");
    }

    // 编译并链接所有C++文件
    build.compile("serialize_structs");
}


fn build_hdc_host() {
    let mut build = cc::Build::new();
    build.cpp(true);
    let files = vec![
        "bounds_checking_function/src/fscanf_s.c",
        "bounds_checking_function/src/fwscanf_s.c",
        "bounds_checking_function/src/gets_s.c",
        "bounds_checking_function/src/memcpy_s.c",
        "bounds_checking_function/src/memmove_s.c",
        "bounds_checking_function/src/memset_s.c",
        "bounds_checking_function/src/scanf_s.c",
        "bounds_checking_function/src/securecutil.c",
        "bounds_checking_function/src/secureinput_a.c",
        "bounds_checking_function/src/secureinput_w.c",
        "bounds_checking_function/src/secureprintoutput_a.c",
        "bounds_checking_function/src/secureprintoutput_w.c",
        "bounds_checking_function/src/snprintf_s.c",
        "bounds_checking_function/src/sprintf_s.c",
        "bounds_checking_function/src/sscanf_s.c",
        "bounds_checking_function/src/strcat_s.c",
        "bounds_checking_function/src/strcpy_s.c",
        "bounds_checking_function/src/strncat_s.c",
        "bounds_checking_function/src/strncpy_s.c",
        "bounds_checking_function/src/strtok_s.c",
        "bounds_checking_function/src/swprintf_s.c",
        "bounds_checking_function/src/swscanf_s.c",
        "bounds_checking_function/src/vfscanf_s.c",
        "bounds_checking_function/src/vfwscanf_s.c",
        "bounds_checking_function/src/vscanf_s.c",
        "bounds_checking_function/src/vsnprintf_s.c",
        "bounds_checking_function/src/vsprintf_s.c",
        "bounds_checking_function/src/vsscanf_s.c",
        "bounds_checking_function/src/vswprintf_s.c",
        "bounds_checking_function/src/vswscanf_s.c",
        "bounds_checking_function/src/vwscanf_s.c",
        "bounds_checking_function/src/wcscat_s.c",
        "bounds_checking_function/src/wcscpy_s.c",
        "bounds_checking_function/src/wcsncat_s.c",
        "bounds_checking_function/src/wcsncpy_s.c",
        "bounds_checking_function/src/wcstok_s.c",
        "bounds_checking_function/src/wmemcpy_s.c",
        "bounds_checking_function/src/wmemmove_s.c",
        "bounds_checking_function/src/wscanf_s.c",

        "src/dep.cpp",

        "src/cffi/host/ctimer.cpp",
        "src/cffi/host/host_usb.cpp",
        "src/cffi/host/host_usb_wrapper.cpp",
        "src/cffi/serial_struct.cpp",
        "src/cffi/transfer.cpp",
        // "src/cffi/uart.cpp",
        // "src/cffi/uart_wrapper.cpp",
        "src/cffi/usb_util.cpp",
        "src/cffi/utils.cpp",
    
        // "src/cffi/oh_usb.cpp",
        "src/cffi/sendmsg.cpp",
        // "src/cffi/usb_wrapper.cpp",
    ];

    println!("cargo:rerun-if-changed={}", "src/dep.cpp");

    // 为每个文件添加一个.file()条目
    for file in files {
        build.file(file);
    }

    // 获取项目根目录
    let project_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // 构造头文件相对路径
    let header_path = project_root.join("bounds_checking_function/include");
    // 添加头文件搜索路径
    build.include(header_path)
         .include(project_root.join("src/cffi"))
         .include("/opt/homebrew/include/")
         .include("/opt/homebrew/include/libusb-1.0/");
    // 指定使用C++17编译
    build.flag_if_supported("-std=c++17");

    // 根据目标操作系统设置不同的C++宏
    if cfg!(target_os = "macos") {  // windows linux
        build.define("HOST_MAC", "1");
    }

    // 编译并链接所有C++文件
    build.compile("hdc_host");
}

fn main() {
    // let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    // if target_os == "macos" {
    //     #[cfg(target_os = "macos")]
    //     build_mac();
    //     println!("cargo:rustc-link-lib=framework=ApplicationServices");
    // }

    // 指定静态库的名称
    let library_name = "lz4";

    // 指定静态库文件所在的目录（请根据实际情况修改）
    let library_dir = "/opt/homebrew/lib/";

    // 输出链接指令
    println!("cargo:rustc-link-lib=static={}", library_name);
    println!("cargo:rustc-link-search=native={}", library_dir);

    build_hdcd();

    build_hdc_host();
    println!("cargo:rerun-if-changed=build.rs");
    
}
