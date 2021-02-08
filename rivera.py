#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

try:
    import frida, argparse, threading, signal, time, os
    from colorama import Fore as F, Back as B, Style as S
except Exception as ex:
    print("[!] ERROR: %s" % ex + S.RESET_ALL)
    print("The following python3 modules are needed: frida, colorama, argparse, threading, signal, time")
    exit(1)

class Package:
    def __init__(self, pkg, script, device):
        self.pkg = pkg
        self.script_txt = script
        self.device = device
        self.alive = None
        self.session = None

    def hook(self, pid):
        print("Hooking %s with PID %d" % (self.pkg, pid))
        self.session = self.device.attach(pid)
        self.script = self.session.create_script(self.script_txt)
        self.script.load()
        self.script.on('destroyed', self.onDestroyed)
        self.alive = 1

    def onDestroyed(self):
        print("%s hook destroyed, scanning for new process" % self.pkg)
        self.alive = None


def end(sig, frame):
    print(F.MAGENTA + "[*] DEBUG: terminating threads and closing the program..." + S.RESET_ALL)
    exit(0)


def parse_conf(conf_file, d):
    global packages
    scripts = dict()
    line_number = 0
    try:
        with open(conf_file, 'r') as configf:
            try:
                for line in configf:
                    line_number += 1
                    if not line[0] == "#":
                        package,script = line.strip().split(' ')
                        if not script in scripts:
                            scripts[script] = open(script, 'r').read()
                        packages.append(Package(package, scripts[script], d))
            except Exception as ex:
                print(F.RED+"[!] ERROR - reading config file (line %d - %s)" % (line_number, line.strip()) +S.RESET_ALL+": %s" % ex)
                exit(1)
    except Exception as ex:
        print(F.RED+"[!] ERROR - opening config file"+S.RESET_ALL+": %s" % ex)
        exit(1)
    return 0


def list_processes(d):
    # Infinite loop updating the process list.
    # Acts as monitor also to check conectivity
    while True:
        global proclist
        try:
            proclist = d.enumerate_processes()
        except Exception as ex:
            print(F.RED+"[!] ERROR: lost connection to frida-server: %s" % ex + S.RESET_ALL)
            os.kill(os.getpid(), signal.SIGINT)
        time.sleep(1)


def check_packages():
    global packages
    global proclist
    if len(packages) > 0:
        for i in packages:
            if not i.alive:
                for j in proclist:
                    if i.pkg == j.name:
                        try:
                            i.hook(j.pid)
                        except Exception as ex:
                            print(F.RED+"[!] ERROR: unable to hook PID %d (%s): %s" % (j.pid, i.pkg, ex) + S.RESET_ALL)


def check_hooks():
    global packages
    # Falta cómo detectar si el proceso está vivo

if __name__ == "__main__":
    # SIGINT handler to close all threads
    signal.signal(signal.SIGINT, end)

    # Set up script arguments
    argp = argparse.ArgumentParser(description="Rivera: profiting from Frida since 1929.")
    argp.add_argument('conf', type=str,  help="config file to read from (incompatible with -i option)")
    argp.add_argument('-l', '--list_devices', action='store_true', help="list available devices")
    argp.add_argument('-u', '--usb', action='store_true', help="onnect to Frida server via USB (as in frida -U)")
    argp.add_argument('-i', '--id', type=str, help="ID of Android device (incompatible with -u option)")
    args = argp.parse_args()

    if args.list_devices:
        try:
            devices = frida.enumerate_devices()
            for d in devices:
                print("%s (%s): %s" % (d.name, d.type, d.id))
        except Exception as ex:
            print(F.RED + "[!] ERROR" + S.RESET_ALL + ": %s" % ex)
            exit(1)
        exit(0)
    if args.id and args.usb:
        print(F.RED+"[!] ERROR"+S.RESET_ALL+": usb and id arguments should not be used together")
        exit(1)

    # Connect to device
    if args.usb:
        try:
            d = frida.get_usb_device()
        except Exception as ex:
            print(F.RED+"[!] ERROR"+S.RESET_ALL+": %s" % ex)
            exit(1)
    elif args.id:
        try:
            d = frida.get_device(args.id)
        except Exception as ex:
            print(F.RED+"[!] ERROR"+S.RESET_ALL+": %s" % ex)
            exit(1)
    print(F.MAGENTA + "[*] DEBUG: Connected to %s (%s)" % (d.name, d.type)+ S.RESET_ALL)

    # Parse config file
    packages = list()
    parse_conf(args.conf, d)

    # Start process monitor thread. If there is no connection to frida anytime it sends a SIGINT signal to end the main process.
    proclist = list()
    monitor = threading.Thread(target=list_processes, args=(d,), daemon=True).start()

    # Main loop
    while True:
        time.sleep(0.5)
        check_packages()
        check_hooks()