# Sicherheit

## Was Hoong-systemScope ist und was nicht

Hoong-systemScope ist ein **Diagnosewerkzeug**. Es liest die Konfiguration eines
Windows-Systems und erklärt, warum ein Eintrag ungewöhnlich aussieht.

Es ist **kein Virenscanner**. Es hat keine Signaturdatenbank, keine Heuristik
für Schadcode und keine Möglichkeit festzustellen, ob ein Programm bösartig ist.
Ein hoher Risikoscore bedeutet „das ist auffällig und verdient einen Blick" —
nicht „das ist Schadsoftware". Umgekehrt bedeutet ein niedriger Score nicht,
dass ein System sauber ist: gut gemachte Schadsoftware ist signiert und liegt an
einem plausiblen Ort.

## Zusagen und ihre Durchsetzung

| Zusage | Wie sie durchgesetzt wird |
|---|---|
| Verändert das untersuchte System nicht | `IRegistryReader` hat keine Schreiboperation; Dateien werden nur mit `FileAccess.Read` geöffnet; Architekturtest verbietet verändernde Aufrufe |
| Führt nichts Gefundenes aus | Architekturtest verbietet `Process.Start`, `ProcessStartInfo`, `ShellExecute`, `CreateProcess` in **allen** Projekten |
| Funktioniert offline | Architekturtest verbietet `HttpClient`, `WebClient`, `Socket`, `WebRequest` und Verwandte in **allen** Projekten; die Signaturprüfung läuft ohne Sperrlistenabruf |
| Sammelt keine Zugangsdaten | Sperrliste in `SensitiveLocations` blockiert `SAM`, `SECURITY`, LSA-Secrets, Credential-Vaults und Browser-Profilverzeichnisse, bevor ein Schlüssel oder Verzeichnis geöffnet wird |
| Verändert keine Benutzerhives | Nicht geladene Hives werden nicht eingehängt, sondern als Lücke im Bericht ausgewiesen |

Der Architekturtest ist eine **lexikalische** Prüfung des Quelltextes. Reflection
oder ein anders benannter P/Invoke könnten daran vorbei. Das ist eine bewusste
Grenze: die Prüfung soll einen Rückschritt laut und absichtlich machen, nicht
unmöglich.

## Umgang mit dem Bericht

Ein Bericht enthält Dateipfade, Kommandozeilen, Publisher-Namen und Hashes des
untersuchten Systems. Er enthält **keine** Zugangsdaten, Cookies oder Tokens,
und `MachineInfo` verzichtet bewusst auf Seriennummern, Maschinen-GUID und
Konto-SIDs — Berichte werden regelmäßig an Fremde weitergegeben, um Hilfe zu
bekommen.

Lange undurchsichtige Zeichenketten in Kommandozeilen (typisch
`powershell -EncodedCommand`) werden gekürzt: ein begrenzter Präfix bleibt als
Beweis erhalten, dazu Gesamtlänge und SHA-256 des Originals. Dennoch gilt: **sieh
dir einen Bericht an, bevor du ihn weitergibst.** Pfade unter einem
Benutzerprofil enthalten den Benutzernamen.

## Rechte

Das Werkzeug läuft ohne Administratorrechte und liefert dann weniger. Es fordert
keine Rechteerhöhung an und braucht keine, um nützlich zu sein.

## Schwachstellen melden

Melde sicherheitsrelevante Fehler über eine private Meldung an die
Repository-Betreuer, nicht über ein öffentliches Issue.
