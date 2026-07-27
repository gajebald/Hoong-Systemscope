# Risikoregeln

Jede Regel prüft genau einen Indikator und liefert höchstens einen Grund mit
einem Punktwert. Die Engine summiert die Punkte, schneidet bei null ab und
ordnet das Ergebnis einer Stufe zu. **Jeder Punkt ist auf eine benannte Regel
zurückführbar** — ein Test in `Analysis.Tests` prüft, dass der Score exakt der
Summe seiner Gründe entspricht.

## Schwellen

| Stufe | ab Punktzahl |
|---|---:|
| Informational | 0 |
| Low | 10 |
| Medium | 25 |
| High | 45 |
| Critical | 70 |

Die Gewichte sind absichtlich zurückhaltend. Für ein `High` braucht es
normalerweise zwei bis drei unabhängige Indikatoren. Ein Werkzeug, das das halbe
System rot färbt, erzieht seine Benutzer dazu, es zu ignorieren — und hat dann
mehr geschadet als genutzt.

## Signatur und Datei

| Regel | Code | Punkte | Bedingung |
|---|---|---:|---|
| `UnsignedBinary` | `RISK_UNSIGNED` | +12 | Keine Signatur, weder eingebettet noch über Katalog |
| `BrokenSignature` | `RISK_SIGNATURE_INVALID` | +40 | Signiert, aber der Inhalt passt nicht mehr dazu |
| `BrokenSignature` | `RISK_SIGNATURE_REVOKED` | +45 | Zertifikat gesperrt |
| `BrokenSignature` | `RISK_SIGNATURE_UNTRUSTED_ROOT` | +25 | Kette endet in einem nicht vertrauten Root |
| `BrokenSignature` | `RISK_SIGNATURE_EXPIRED` | +10 | Abgelaufen ohne gültigen Zeitstempel |
| `TrustedSystemBinary` | `RISK_TRUSTED_SYSTEM_BINARY` | **−8** | Microsoft-signiert **und** unterhalb `System32` oder `WinSxS` |
| `MissingTarget` | `RISK_MISSING_TARGET` | +8 | Zieldatei existiert nicht |

Zwei Punkte verdienen eine Erklärung.

**Katalogsignaturen zählen als signiert.** Die meisten Windows-Systemdateien
tragen keine eingebettete Signatur; ihr Vertrauen kommt aus einem Katalog unter
`System32\CatRoot`. Wer sie als unsigniert meldet, produziert einen Bericht, der
fast nur aus Falschmeldungen besteht.

**Der Score-Senker verlangt beide Hälften.** Eine Microsoft-signierte Datei in
einem Temp-Verzeichnis ist nicht beruhigend, und ein unbekannter Herausgeber in
`System32` ebenso wenig.

## Ort

| Regel | Code | Punkte | Bedingung |
|---|---|---:|---|
| `SuspiciousLocation` | `RISK_LOCATION_RECYCLE_BIN` | +45 | Ausführung aus dem Papierkorb |
| `SuspiciousLocation` | `RISK_LOCATION_TEMP` | +25 | Ausführung aus einem Temp-Verzeichnis |
| `SuspiciousLocation` | `RISK_LOCATION_DOWNLOADS` | +22 | Ausführung direkt aus Downloads |
| `SuspiciousLocation` | `RISK_LOCATION_DRIVE_ROOT` | +20 | Datei liegt direkt in der Laufwerkswurzel |
| `SuspiciousLocation` | `RISK_LOCATION_NETWORK` | +18 | Laden von einer Netzwerkfreigabe |
| `SuspiciousLocation` | `RISK_LOCATION_APPDATA` | +10 | Ausführung aus AppData |
| `WritableDirectory` | `RISK_WRITABLE_DIRECTORY` | +35 | Programm mit Systemrechten in einem für Standardbenutzer beschreibbaren Verzeichnis |
| `UnquotedServicePath` | `RISK_UNQUOTED_SERVICE_PATH` | +30 | Dienstpfad mit Leerzeichen ohne Anführungszeichen |

`SuspiciousLocation` liefert **einen** Grund, den stärksten zutreffenden. Ein
Pfad, der zugleich temporär und in AppData liegt, wird nicht doppelt gezählt.

`WritableDirectory` gilt nur für Einträge, die mit Systemrechten laufen. Ein
Programm, das der Benutzer ohnehin ersetzen könnte und das als dieser Benutzer
läuft, gewährt niemandem etwas Neues.

## Namen

| Regel | Code | Punkte | Bedingung |
|---|---|---:|---|
| `DeceptiveName` | `RISK_BIDI_OVERRIDE` | +50 | Unicode-Richtungsumkehr im Namen |
| `DeceptiveName` | `RISK_DOUBLE_EXTENSION` | +35 | Dokument- plus ausführbare Endung, etwa `rechnung.pdf.exe` |

Ein Right-to-Left-Override lässt `rechnung<U+202E>gnp.exe` als
`rechnungexe.png` erscheinen. Dafür gibt es keinen gutartigen Grund.

## Kommandozeile und Interpreter

| Regel | Code | Punkte | Bedingung |
|---|---|---:|---|
| `ScriptInterpreter` | `RISK_SCRIPT_INTERPRETER` | +10 … +30 | Ein Autostart startet einen Interpreter statt einer Anwendung |
| `ObfuscatedCommand` | `RISK_OBFUSCATED_COMMAND` | +12 … +55 | Kombination verschleiernder Schalter |

Die Interpreter-Gewichte reichen von `msiexec.exe` (+10) über `powershell.exe`
(+18) bis `mshta.exe` und `cmstp.exe` (+30). Alle diese Programme gehören zu
Windows und sind von Microsoft signiert — genau deshalb werden sie benutzt. Wer
den Eintrag nur an seiner Signatur misst, spricht ihn frei. Interessant ist,
dass ein Persistenzpunkt einen Interpreter startet.

`ObfuscatedCommand` bewertet die **Kombination**: verstecktes Fenster, kein
Profil, umgangene Ausführungsrichtlinie, base64-kodierte Nutzlast, Inline-Download.
Einzeln sind das gewöhnliche Optionen; `-NoProfile` allein löst nichts aus. Der
Beitrag ist bei 55 gedeckelt, damit eine Regel den Gesamtscore nicht dominieren
kann.

`ScriptInterpreter` greift nur bei Persistenzkategorien. Ein PowerShell-Fenster,
das der Benutzer geöffnet hat, ist keine Persistenz.

## Besondere Persistenzpunkte

| Regel | Code | Punkte | Bedingung |
|---|---|---:|---|
| `SensitivePersistence` | `RISK_IFEO_DEBUGGER` | +35 | Debugger für ein anderes Programm registriert |
| `SensitivePersistence` | `RISK_APPINIT_DLL` | +30 / +12 | Bibliothek wird systemweit injiziert (aktiv / abgeschaltet) |
| `SensitivePersistence` | `RISK_WINLOGON_HOOK` | +30 | Winlogon-Wert weicht vom Windows-Standard ab |
| `HiddenTask` | `RISK_HIDDEN_ELEVATED_TASK` | +25 | Versteckte Aufgabe **und** erhöhte Rechte |
| `HiddenTask` | `RISK_HIDDEN_TASK` | +8 | Nur versteckt |
| `HostsRedirect` | `RISK_HOSTS_REDIRECT` | +20 | Name zeigt auf eine echte Adresse |
| `HostsRedirect` | `RISK_HOSTS_BLOCK` | +4 | Name auf Loopback, also blockiert |

`HiddenTask` unterscheidet bewusst: Windows liefert viele versteckte
Wartungsaufgaben mit, „versteckt" allein sagt also wenig. Versteckt **und**
erhöht ist die Kombination, die zählt.

`HostsRedirect` unterscheidet ebenso: eine Loopback-Zuordnung blockiert einen
Namen — so arbeiten Werbe- und Update-Blocker, das ist erwähnenswert, aber kein
Alarm. Ein Name, der auf eine echte Adresse zeigt, ist etwas anderes.

## Eine eigene Regel hinzufügen

```csharp
public sealed class MyRule : RiskRuleBase
{
    public override string RuleId => "MyRule";

    public override RiskReason? Evaluate(ScanEntry entry, RiskEvaluationContext context) =>
        Bedingung(entry) ? Reason("RISK_MY_CODE", "Kurze Begründung.", 15, entry.ExecutablePath) : null;
}
```

Dann in `RiskRules.CreateDefaultSet()` eintragen und in `Analysis.Tests` einen
Test ergänzen, der sowohl den Treffer als auch den Nicht-Treffer prüft. Die
Nicht-Treffer-Hälfte ist die wichtigere: Falschmeldungen sind das eigentliche
Risiko dieses Werkzeugs.
