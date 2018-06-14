var blocked = Memory.allocUtf8String('blocked\n');

Interceptor.attach(Module.findExportByName(null, 'printf'), {
    onEnter: function(args) {
        var str = Memory.readUtf8String(args[0]);
        send(str);

        if (str.match(/%/) !== null) {
            args[0] = blocked;
        }
    }
});
