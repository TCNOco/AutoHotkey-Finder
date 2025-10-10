# TroubleChute Autohotkey Finder

The TroubleChute Autohotkey Finder is a Windows utility written in C++ that helps you locate and manage running AutoHotkey scripts on your system. It is designed to be lightweight, fast, and requires no additional redistributables to run.

This fixes increasingly common annoying Anti-Cheat errors like Battlefield 6's:

![Battlefield 6 - Authotkey Anti-Cheat Error](img/bf6.webp)

If you know of other software that cause issues, or have improvements please open an [issue](https://github.com/TCNOco/AutoHotkey-Finder/issues/new) or [pull request](https://github.com/TCNOco/AutoHotkey-Finder/pulls)!

## No-download usage
You can use the software by running a command in an Admin PowerShell window - No releases GitHub downloads, nothing!
1. Hit Start/Windows and type `PowerShell`. Run PowerShell as Admin.
2. Type: `iex (irm ahk.tc.ht)` and press Enter.
3. Use the program as below.

This works because of my other project, https://github.com/TCNOco/TcNo-TCHT. This lets you run scripts and more with just a simple command!

## Usage
1. Download the latest release from the [Releases](https://github.com/TCNOco/AutoHotkey-Finder/releases) page.
2. Run `Autohotkey Finder.exe` (no installation required).
3. The application will display a list of running AutoHotkey scripts and their details.
4. Enter a number from the screen to close those applications, or do so manually.

Once programs using AutoHotkey are closed, games like Battlefield 6 should no longer display AutoHotkey-related errors.

![Using the program](img/process.webp)

## Building from Source
This project is built with Visual Studio and MSBuild. To build manually:

1. Open `Autohotkey Finder.sln` in Visual Studio.
2. Select the `Release` configuration and `x64` platform.
3. Build the solution (Ctrl+Shift+B).

Alternatively, you can use the provided GitHub Actions workflow to build and release automatically on pushes to the `main` branch.

## Contributing
Contributions, issues, and feature requests are welcome! Please open an issue or submit a pull request on GitHub.

## License
This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.
