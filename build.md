
## 简要描述如何在在mac上编译hdc

>仅验证了m1 mac

方便调试harmoneyOS的hdc协议，可以源码编译hdc的client/server组件。

hdc代码仓库有C++和rust两套实现，通过与华为工程师沟通，目前现状如下：
1. daemon经切换到rust上了，也就是说鸿蒙Next最新版的hdc daemon目前是rust实现的，C++版本已经废弃了
2. client和server目前依然是C++版本构建的，但是rust版本正在快速开发，预计2024年5月底切换到rust版本，未来C++版本也会停止维护


## 编译C++版本

安装第三方依赖
```
brew install libuv libusb
```

下载代码，并安装harmoney自研的带安全检查的基础库

```
mkdir openharmoney && cd openharmoney 
git clone git@github.com:prife/hdc.git
git clone git@gitee.com:openharmony/third_party_bounds_checking_function
cd third_party_bounds_checking_function  && git checkout OpenHarmony-4.1-Release && cd ../
```

编译
```
cd  hdc/src/
mkdir build && cd build
cmake ../
make -j
```

也可以使用vscode/clion等IDE编译并调试

## 编译rust版本

目前官方没有提供cargo.toml文件，还无法独立编译，但开发者表示未来会提供使用rust工具链独立编译的wiki，敬请期待吧。
