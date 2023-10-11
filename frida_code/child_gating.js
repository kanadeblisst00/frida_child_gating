// 根据%读取printf的参数
function vspritf(format_str, args){
    let printf_args = [];
    if (format_str.indexOf("%") === -1) {
        return printf_args;
    }
    var pos = 0;
    for (let index = 0; index < format_str.length; index++) {
        pos = format_str.indexOf("%", pos);
        if(pos == -1)
            break;
        var format_ch = format_str.substr(pos+1, 1);
        let length = printf_args.length;
        let arg;
        switch (format_ch) {
            case "s":
                arg = args[length+1].readAnsiString()
                break;
            case "d": 
                arg = args[length+1].toInt32()
                break;
            case "p":
                arg = args[length+1].toInt32()
                break;
            case "f":
                arg = args[length+1]
                break;
            default:
                arg = args[length+1]
                break;
        }
        printf_args.push(arg);
        pos += index+2;
    }
    return printf_args;
}

let ProcessModAddress = Process.findModuleByName('ForkProcess.exe');
// Offset是在x64dbg里计算的偏移，
// 本来我想使用Module.findExportByName(null, "printf")，发现得到的偏移不知道是哪里的
let Offset = '0x1070';
// 如果没有获取到ForkProcess，说明是子进程
if(!ProcessModAddress){
    ProcessModAddress = Process.findModuleByName('SubProcess.exe');
    Offset = '0x1010';
}
// 通过偏移计算printf的实际地址
let pvPrintf = ProcessModAddress.base.add(Offset);
// 调用Windows获取进程pid的api
let pvGetCurrentProcessId = Module.findExportByName("kernel32.dll", "GetCurrentProcessId")
var GetCurrentProcessId = new NativeFunction(pvGetCurrentProcessId, 'uint32', []);

console.log(GetCurrentProcessId(), Offset, pvPrintf)
// hook函数
Interceptor.attach(pvPrintf, {
    onEnter: function (args) {
        let format_str = args[0].readAnsiString()
        send({
            "format_str": format_str,
            "format_args": vspritf(format_str, args)
        })
    } 
});