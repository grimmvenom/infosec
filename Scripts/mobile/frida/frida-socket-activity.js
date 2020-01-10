Java.perform(function () { // avoid java.lang.ClassNotFoundException
        this
        .getModuleByName({ linux: 'libc.so', darwin: 'libSystem.B.dylib', windows: 'ws2_32.dll' }[Process.platform])
        .enumerateExports().filter(ex => ex.type === 'function' && ['connect', 'recv', 'send', 'read', 'write'].some(prefix => ex.name.indexOf(prefix) === 0))
        .forEach(ex => {
          Interceptor.attach(ex.address, {
            onEnter: function (args) {
              var fd = args[0].toInt32();
              if (Socket.type(fd) !== 'tcp')
                return;
              var address = Socket.peerAddress(fd);
              if (address === null)
                return;
              console.log(fd, ex.name, address.ip + ':' + address.port);
            }
          })
        })
    });