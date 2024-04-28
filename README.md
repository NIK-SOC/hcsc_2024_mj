# HCSC 2024 - MJ's challenges
Source code for some of [MJ's](https://github.com/Diniboy1123) CTF challenges for the HCSC 2024 event.

The repository is fairly huge, this is mainly due to the fact that I have included pre-built binaries for some challenges, so you can easily reproduce each step and we don't have to rebuild the binaries every time.

Most of the source is messy and might require some adjustments to have it working outside of our infrastructure. In doubt, feel free to contact me. As an excuse: this code was never meant to be public, the writeups and PoC scripts were meant to be used internally. I just wanted to share it with the participants of the event.

Each challenge has a README.md file with a short, usually spoiler free description and a little how-to. If you expand the spoiler part you also see a full write-up. Most subfolders should have a PoC script ready for you as well with one or more possible solutions.

There are many subfolders, many of them are using different OSS libraries and therefore have different licenses. Therefore I haven't included a LICENSE file in the root folder. If you want to use any of the code, do some research on the used libraries and their licenses. I tried to keep the original licenses for each used library in the respective subfolder.

## Remarks

- The dataset images were removed from ctf-2bernot2bee. If you would like to try that challenge, you must obtain the images yourself from [here](https://www.kaggle.com/code/gpreda/honey-bee-subspecies-classification) and place them in the `assets/bee_imgs` folder. Kaggle requires a login to download the dataset, and we respect that.
- Both Patch Adams and Tutorial challenges come in a simplified version than the one used in the event. This way its easier for you to deploy. The solution doesn't change.
- Descriptions for the challenges may differ from the ones used during the event. This is simply because the organizers preferred the descriptions to be in Hungarian, therefore they were altered a little to better fit the language.

## Credits

- To Peter Zaletnyik from Óbuda University for answering many of my questions regarding IPv6 thus making the `ctf-return_of_jack` challenge possible.
- To kocka from Óbuda University and the HCST CTF team for the `radare2` inspiration in the `ctf-patch_adams` challenge.