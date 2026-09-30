# Project | Horus

<p align="center">
  <img src="https://i.ibb.co/kcvtBM0/Screenshot-2024-04-15-at-7-01-47-PM.png"/>
</p>

## 🚀 About Horus

Horus is an all-in-one encompassing tool for investigations assistance, from API leveraging to compiling data too. Its your pre-ops buddy! 

## Installation and Usage Instructions
To get started with this project, follow these steps:

1. Clone this repository.
2. Move to the 'horus' directory.
3. Install dependencies using the following command: ```pip install -r requirements. txt```
4. In the 'sentinel' directory, run ```python3 horus.py```

## API Configuration
To configure the APIs necessary for usage of certain commands, you can either manually enter them, or use the 'apicon' command

To manually configure API keys, navigate to ```/src/modules/var/pipes/api_config.json```. Enter your API keys in their corresponding entries.

## 🤝 Current Contributors

- [Maestro](https://github.com/digitalized-snake) (Me) | Project Lead and Developer

## Contributing
- If you notice a bug or want to request a feature, make an issue with the appropriate tag
- If you would like to fix a bug or add a feature yourself, make a PR and I'll take a look
- If you would like to become a long-term maintainer/contributor, contact me
- For any other inquiries, you may also contact me

Contact info:
- Email: digitalizedsnake@gmail.com
- Discord: maestro.hq or through the [community server](https://discord.gg/PhkqXAT7Ax)
  
## Intended Features
```  
🟢 = Fully implemented or more than 80% done

🟡 = Partially implemented / In development

🔴 = To be implemented
```

<p align="center">
  <img src="https://i.ibb.co/Lrzj2Mf/Screenshot-2024-04-15-at-7-02-02-PM.png"/>
</p>


## 🤝 Acknowledgements

- [Fox](https://github.com/1T57H3F0X) | Was Previously Project Manager
- [Tornado](https://github.com/digitalsilicon) | Was Previously QA
- [Mart](https://github.com/marvhus) | Was Previously Sr Dev
- [Maestro](https://github.com/digitalized-snake) (Me) | Was Previously Jr Dev
- [Mu](https://github.com/IamMU) | Was Previously Jr Dev

*Some code used can be attributed to [Fox](https://github.com/FoxIDK) and [Askerdyne Ltd.](https://askerdyne.com/), specifically the 'Loki' encryption toolset.*


## Optional Laya / System-One forensic triage

Horus now includes a `Triage` command for classifying **already-collected**
investigation evidence. It does not collect evidence, run scans, exploit hosts,
contain systems, modify files, or replace deterministic IOC/forensic analysis.

```bash
export HORUS_SYSTEM_ONE_MODE=off
export HORUS_SYSTEM_ONE_BASE_URL=http://127.0.0.1:8000
export HORUS_SYSTEM_ONE_API_KEY=
export HORUS_SYSTEM_ONE_TIMEOUT_SECONDS=1.5
```

Use `shadow` or `advisory` only after validating the classifier on your own
investigation data. Provider errors fail open and leave existing Horus workflows
unchanged. Human authorization remains required for remediation actions.
