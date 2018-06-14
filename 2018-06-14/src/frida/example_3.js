Interceptor.attach(Module.findExportByName(null, 'printf'), {
    onEnter: function (args) {
        var str = Memory.readUtf8String(args[0]);
        send(str);

        if (str.match(/%/) !== null)
            Memory.writeUtf8String(args[0], 'blocked\n');
    }
});