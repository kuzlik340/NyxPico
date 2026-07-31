#!/bin/bash
picotool erase
sleep 0.5
picotool reboot
sleep 2
picotool partition create trustzone_pt.json trustzone_pt.uf2
picotool load trustzone_pt.uf2
sleep 2
picotool reboot
sleep 5
picotool load build/two_worlds/nonsecure.uf2
picotool load build/two_worlds/secure.uf2
sleep 2
picotool reboot