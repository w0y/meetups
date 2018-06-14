Interceptor.attach(Module.findExportByName(null, 'fork'), {
    onLeave: function (retval) {
        if (retval !== 0)
        	send(retval);
    }
});
