#! /usr/bin/env python

import sys
import os
import argparse
import subprocess
import json

"""
Config file (default ~/.config/sx-builder.json):

{
    "SRC_ROOT": "/tmp/smithproxy/",
    "SRC_REST": "tools/docker/0.9/build/",
    "SRC_BRANCH": "master",
    "FTP_PASS": "password",
    "FTP_UPLOAD_USER": "ftpuser",
    "FTP_UPLOAD_PATH": "ftp.site.org/download/",
    "CURL_UPLOAD_OPTS": ""
}
"""

CFG_DEFAULT = "~/.config/sx-builder.json"

SRC_ROOT = ""
SRC_REST = ""
SRC_BRANCH = ""
FTP_PASS = ""
FTP_UPLOAD_USER = ""
FTP_UPLOAD_PATH = ""
CURL_UPLOAD_OPTS = ""

parser = argparse.ArgumentParser(description='Smithproxy builder')

top_group = parser.add_argument_group()

build_group = top_group.add_argument_group()
build_group.add_argument('--targets', type=str, help='builds to ... build', nargs='*')

build_group.add_argument('--exclude', type=str, nargs='*', help='builds to exclude')

build_group.add_argument('--hosts', type=str, nargs='*', help='hosts - localhost or remote hostname')

build_group.add_argument('--proxy', type=str, nargs='?', help='hosts - localhost or remote hostname')


misc_group = top_group.add_argument_group()
misc_group.add_argument('--list', action='store_true')
misc_group.add_argument('--cleanup', action='store_true')
misc_group.add_argument('--config', type=str, nargs=1, help="custom config file (default %s)" % (CFG_DEFAULT))


def list_dockers(arg_filter=None, out_filter=None):
    
    to_ret = []
    my_filter = []
    my_exclude = []

    if arg_filter:
        my_filter = arg_filter

    if out_filter:
        my_exclude = out_filter

    if not my_filter:
        my_filter.append("all")

    for root, dirs, files in os.walk(SRC_ROOT):

        for entry in files:
            if entry == "Dockerfile":
                
                fp = os.path.join(root, entry)
                name = root.split("/")[-1]
                
                for f in my_filter:
                    if f in name or f == "all":
                        
                        include = True
                        
                        for of in my_exclude:
                            if of in name:
                                include = False
                        
                        if include:
                            to_ret.append(fp)
                            break

    return to_ret


def run_build(host, files, arg_http_proxy=None, arg_cleanup=False):

    cmd_pre = ""
    if arg_cleanup:
        cmd_pre = "docker system prune -a -f\; "

    for dockerfile in files:       
        cmd_base = cmd_pre + "docker build --rm --no-cache --build-arg FTP_UPLOAD_PWD=%s \
                            --build-arg FTP_UPLOAD_USER=%s \
                            --build-arg FTP_UPLOAD_PATH=%s \
                            --build-arg SX_BRANCH=%s \
                            --build-arg CURL_UPLOAD_OPTS=%s " % (FTP_PASS, FTP_UPLOAD_USER, FTP_UPLOAD_PATH, SRC_BRANCH, CURL_UPLOAD_OPTS)

        # reset - cmd_pre is run only once
        cmd_pre = ""

        tag = "echo \"===\"; date -R; echo \"%s: %s\"; echo \"===\"" % (host, dockerfile)
                            
        if arg_http_proxy:
            cmd_base = cmd_base + " --build-arg http_proxy=http://" + arg_http_proxy
                
        if host == "localhost":
            cmd_local = cmd_base + " -f %s `mktemp -d`" % (dockerfile,)
            subprocess.run("(" + tag + cmd_local + ") >> /tmp/builder-%s.log 2>&1" % (host,), shell=True)
                
        else:
        
            cp_cmd = "scp %s root@%s:/tmp/Dockerfile.current" % (dockerfile, host)
            
            ssh_cmd = "ssh root@%s -C " % (host) + cmd_base + " -f /tmp/Dockerfile.current \`mktemp -d\`"
            
            ssh_cmd = "(" + tag + ";" + cp_cmd + ";" + ssh_cmd + ") >> /tmp/builder-%s.log 2>&1" % (host,)
            
            # print(">>> " + ssh_cmd)
            # sys.exit(0)
            
            try:
                subprocess.run(ssh_cmd, shell=True)
            except KeyboardInterrupt as k_e:
                err_msg = "echo \"Ctrl-C hit: terminated %s\" >> /tmp/builder-%s.log" % (k_e, host)
                subprocess.run(err_msg, shell=True)
                raise k_e
                
            except Exception as ee:
                err_msg = "echo \"terminated abruptly: %s\" >> /tmp/builder-%s.log" % (ee, host)
                subprocess.run(err_msg, shell=True)
                raise ee
            

def load_config(fnm):
    
    global SRC_ROOT
    global SRC_REST, SRC_BRANCH, FTP_PASS, FTP_UPLOAD_USER, FTP_UPLOAD_PATH, CURL_UPLOAD_OPTS
    
    try:
        cfg = json.load(open(os.path.expanduser(fnm)))
        
        SRC_ROOT = cfg["SRC_ROOT"]
        SRC_REST = cfg["SRC_REST"]
        SRC_BRANCH = cfg["SRC_BRANCH"]
        FTP_PASS = cfg["FTP_PASS"]
        FTP_UPLOAD_USER = cfg["FTP_UPLOAD_USER"]
        FTP_UPLOAD_PATH = cfg["FTP_UPLOAD_PATH"]
        CURL_UPLOAD_OPTS = cfg["CURL_UPLOAD_OPTS"]
        
    except Exception as e:
        print("cannot load secrets: " + str(e))
        sys.exit(-1)


if __name__ == '__main__':
    
    main_pid = os.getpid()
    children = []

    
    try:

        args = parser.parse_args(sys.argv[1:])
        
        targets = []
        exclude = []
        dockerfiles = []
        http_proxy = None
        cleanup = False

        if args.config:
            load_config(args.config[0])
        else:
            load_config(CFG_DEFAULT)


        os.chdir(SRC_ROOT)

        if args.targets:
            for t in args.targets:
                targets.append(t)

        if args.exclude:
            for e in args.exclude:
                exclude.append(e)
            
        dockerfiles = list_dockers(targets, exclude)
        
        if args.list:
            for d in dockerfiles:
                print("%s" % d)
            sys.exit(0)

        if args.proxy:
            http_proxy = args.proxy

        if args.hosts:

            if args.cleanup:
                cleanup = True

            for h in args.hosts:
                
                pid = os.fork()
                if pid == 0:
                    print("%s host child process: %s" % (h, str(dockerfiles)))
                    run_build(h, dockerfiles, arg_http_proxy=http_proxy, arg_cleanup=cleanup)
                    print("%s host child finished: %s" % (h, str(dockerfiles)))
                    sys.exit(0)
                else:
                    children.append(pid)
        
        print(str(children))

        if len(children) > 0 and os.getpid() == main_pid:
            print("waiting children to finish")
            for ch in children:
                os.waitpid(ch, 0)
        
    except KeyboardInterrupt as e:
        if os.getpid() == main_pid:
            print("Ctrl-C: bailing")
