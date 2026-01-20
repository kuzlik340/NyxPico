#!/bin/bash
picotool erase
sleep 0.5
picotool reboot
sleep 2
picotool partition create trustzone/trustzone_pt.json trustzone/trustzone_pt.uf2
picotool load trustzone/trustzone_pt.uf2
sleep 2
picotool reboot
sleep 5
picotool load build/trustzone/hello_trustzone/hello_trustzone.uf2
picotool load build/trustzone/hello_trustzone/hello_trustzone_s.uf2
sleep 2
picotool reboot