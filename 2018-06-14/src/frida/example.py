#!/usr/bin/env python2
import frida

# Just read a file into a string
def load_js(file):
    with open(file) as f:
        return f.read()

# Initialize script and assign message handler
def load_script(session, file, handler):
    s = session.create_script(load_js(file))

    def ack_cb(message, data):
    	handler(message, data)

    s.on('message', handler)
    s.load()
    return s

# A default message handler
def default_callback(message, data):
	print(message)

# Track fork calls in chromium
def chromium_example():
	session = frida.attach('chromium')
	def print_pid(message, data):
		print("Forked to PID: {}".format(int(message['payload'], 16)))
	script = load_script(session, './example_1.js', print_pid)

	return session, script

# Only run this code if not imported
if __name__ == "__main__":
	pass