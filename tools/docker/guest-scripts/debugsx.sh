#!/usr/bin/env bash

gdbserver :1112 --attach `pidof smithproxy` &