# TasmoUtil
A rudimentary tool to provision your Tasmota devices based on configurable templates, and other assorted utilities.
Uses https://github.com/tasmota/decode-config to export/import device configurations

## Setup:
- `pip install -r requirements.txt`
- `python3 TasmoUtil.py scan`
    - Follow the prompts. This will scan your network for tasmota devices, export their current configs, and create a stub `devices.jsonc` file.
- Use the json files created in the `device_configs` directory to create your templates, and save them in the `template_configs` directory as your templates. In most cases they do not need to be edited, only copied/renamed.
- Update `devices.jsonc` to map your templates to your devices, and enable those devices.

## Usage:
* `python3 TasmoUtil.py scan`
  * Scan your network for tasmota devices. If `devices.jsonc` doesn't exist or doesn't have any data, it will be created/populated with devices found in the scan. Otherwise it will show only devices not listed in `devices.jsonc` and print JSON that you can add to `devices.jsonc`.
* `python3 TasmoUtil.py backup` 
  * Export fresh device configs for devices listed in `devices.jsonc`
* `python3 TasmoUtil.py deploy`
  * Deploy configs to the device(s) of your choice
* `python3 TasmoUtil.py command`
  * Run a command against the device(s) of your choice
* `python3 TasmoUtil.py devgroups`
  * Queries device group status for devices listed in `devices.jsonc` and checks for devices that don't see all other members in that group
