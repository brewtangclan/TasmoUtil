# tasmota-config-generator
A rudimentary tool to configure your Tasmota devices based on configurable templates.
Uses https://github.com/tasmota/decode-config to export/import device configurations

## Setup:
- `pip install -r requirements.txt`
- `python3 tasmota_configurator.py init`
    - Follow the prompts. This will scan your network for tasmota devices, export their current configs, and create a stub `devices.jsonc` file.
- Use the json files created in the `device_configs` directory to create your templates, and save them in the `template_configs` directory as your templates
- Update `devices.jsonc` to map your templates to your devices, and enable those devices.

## Usage:
* `python3 tasmota_configurator.py get-configs`: Export fresh device configs for devices listed in `devices.jsonc`
* `python3 tasmota_configurator.py deploy`: Guided deployment (select which devices to deploy)
* `python3 tasmota_configurator.py deploy-all`: Bulk deployment to all enabled devices in `devices.jsonc`
* More coming soon!
