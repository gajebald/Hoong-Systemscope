# Sicherheits- und Qualitätsregeln

Dieses Dokument beschreibt, welche Zusagen Hoong-systemScope macht und an
welcher Stelle im Code sie durchgesetzt werden. Zusagen, die nur in einer README
stehen, erodieren leise: ein bequemer Aufruf hier, ein Telemetrie-Ping dort, und
die Eigenschaft ist weg, während der Text sie weiter behauptet.

## 1. Schreibgeschützt per Typsystem

`IRegistryReader` und `IRegistryKey` in
`src/Hoong-systemScope.Core/Abstractions/IRegistryReader.cs` besitzen
ausschließlich lesende Mitglieder. Es gibt kein `SetValue`, kein `CreateSubKey`,
kein `DeleteValue`. Schreibzugriff ist nicht durch eine Laufzeit-Fahne
abgeschaltet, die jemand umlegen könnte — er ist nicht ausdrückbar.

Ein Test (`The_registry_abstraction_exposes_no_write_operation`) prüft die
Schnittstellendatei zusätzlich lexikalisch, damit eine spätere Ergänzung
auffällt.

## 2. Verbotene APIs

`tests/Hoong-systemScope.Core.Tests/ReadOnlyGuaranteeTests.cs` durchsucht den
Quelltext jedes Projekts. Kommentare werden vorher entfernt, damit das
Dokumentieren eines verbotenen Aufrufs — wie in dieser Datei — die Prüfung nicht
auslöst.

**In allen Projekten verboten**

* Prozessstart: `Process.Start`, `ProcessStartInfo`, `ShellExecute`, `CreateProcess`, `WinExec`
* Netzwerk: `HttpClient`, `WebClient`, `WebRequest`, `HttpListener`, `System.Net.Sockets`, `TcpClient`, `UdpClient`, `new Socket`, `Dns.GetHost`

**Zusätzlich in Core, Collectors, Analysis und Windows verboten**

* Dateiänderung: `File.Delete`, `File.WriteAll*`, `File.Create`, `File.Move`, `File.Copy`, `Directory.Delete`, `Directory.CreateDirectory`, `FileMode.Create`, `FileAccess.Write`, `new StreamWriter`
* Registryänderung: `SetValue(`, `DeleteValue`, `DeleteSubKey`, `CreateSubKey`, `RegSetValue`, `RegCreateKey`, `RegDeleteKey`, `RegDeleteValue`
* Prozess- und Dienststeuerung: `.Kill(`, `ServiceController`

`Export`, `ViewModels`, `Cli` und `Wpf` sind von der Datei-Gruppe ausgenommen,
weil sie den Bericht schreiben — aber ausschließlich dorthin, wohin der Benutzer
sie geschickt hat.

## 2a. Die Oberfläche kann nichts verändern

`IScanService`, der einzige Vertrag, gegen den die Desktop-Oberfläche arbeitet,
kennt fünf Operationen: scannen, zweimal rendern, laden, speichern. Es gibt
keine Methode zum Entfernen, Deaktivieren, Beenden oder in Quarantäne
Verschieben.

Eine entsprechende Schaltfläche ließe sich also nicht ergänzen, ohne zuerst
diesen Vertrag zu erweitern — was auffällt. Zusätzlich prüft ein Test in
`ViewModels.Tests`, dass kein Mitglied des `MainViewModel` oder des Vertrags
nach `delete`, `remove`, `disable`, `kill`, `terminate`, `quarantine`, `fix`
oder `repair` benannt ist.

**Grenze der Prüfung.** Sie ist lexikalisch. Reflection, `Delegate`-Umwege oder
ein anders benannter P/Invoke kämen daran vorbei. Ihr Zweck ist, ein Abrutschen
laut zu machen, nicht es unmöglich.

## 3. Dateizugriff

`WindowsFileSystemProbe.OpenRead` öffnet mit `FileAccess.Read` und
`FileShare.ReadWrite | FileShare.Delete`. Die Freigabe ist wichtig: eine Prüfung,
die das Image eines laufenden Programms exklusiv sperrt, tut genau das, was das
Werkzeug zu unterlassen verspricht.

## 4. Sperrliste für sensible Orte

`src/Hoong-systemScope.Core/Security/SensitiveLocations.cs` blockiert vor jedem
Öffnen:

* Registry: `SAM`, `SECURITY`, `LSA\Secrets`, `Policy\Secrets`, Credential- und
  Vault-Schlüssel, `DefaultPassword`
* Dateisystem: DPAPI-Schlüsselverzeichnisse, Browser-Profilverzeichnisse von
  Chrome, Edge, Firefox und Brave, `Cookies`, `Login Data`

Ein Autostart-Eintrag lässt sich ohne diese Orte vollständig beschreiben. Sie zu
lesen brächte nichts und würde einen Bericht, der oft weitergegeben wird,
gefährlich machen.

## 5. Redaktion mit Augenmaß

`CommandLineRedactor` kürzt lange undurchsichtige Zeichenketten in
Kommandozeilen — in der Praxis `powershell -EncodedCommand`-Nutzlasten, die
Kilobytes groß werden können.

Vollständiges Entfernen wäre falsch: der kodierte Befehl ist der wertvollste
Indikator am Eintrag. Vollständiges Behalten wäre ebenfalls falsch. Der
Kompromiss: begrenzter Präfix als Beweis, dazu Gesamtlänge und SHA-256 des
Originals, damit zwei Berichte auf diesem Wert weiterhin exakt vergleichbar
bleiben.

## 6. Degradieren statt scheitern

* Ein Collector, der eine Ausnahme wirft, wird als `ScanError` vermerkt; die
  übrigen laufen weiter.
* Fehlende Rechte erzeugen eine Warnung mit dem betroffenen Ort, keinen Abbruch.
* Ein abgebrochener Scan liefert das bisher Gesammelte zurück.
* `ScanError` enthält Ausnahmetyp und Meldung, aber **nie** einen Stacktrace:
  diagnostisch bringt er nichts und er verrät lokale Pfade.

## 7. Bewusste Auslassungen

* **Keine Sperrlistenprüfung bei Signaturen.** Sie bräuchte Netzwerkzugriff.
* **Kein Einhängen fremder Hives.** Das wäre eine Systemänderung. Nicht geladene
  Profile erscheinen als Lücke.
* **Kein Ausführen zur Metadatengewinnung.** Versionsressourcen werden geparst,
  nicht durch Starten des Programms erfragt.
