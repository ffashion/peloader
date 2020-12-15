![C/C++ CI](https://github.com/ffashion/peloader/workflows/C/C++%20CI/badge.svg)
# 编译

1. make 

# 执行

1. 方式1(需要在Linux或者在wsl下)
   1. ./peloader 
      1. 默认需要此文件夹下有个test.exe的文件
2. 方式二
   1. ./peloader yourexename.exe 



# 实现效果

1. 目前只实现了在程序中加了一段"前置"显示错误框的代码，以后可能增加其他的



# 其他

1. 由于目前使用绝地地址定位MessageBox所以如果你也需要执行此代码，需要修改238行的绝对地址
   1. 在ollydbg中设置MassageBox断点，执行指令`bp MessageBoxA`找到此断点所在的绝对地址，复制进去即可
   2. 注意每次重启电脑需要执行上述操作