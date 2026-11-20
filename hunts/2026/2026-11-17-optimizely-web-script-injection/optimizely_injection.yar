/*
  Cyber-Threat.net Hunt Lab, 17 November 2026. MIT licence.
  Scan saved copies of Optimizely snippets (cdn.optimizely.com/js/<id>.js or
  self-hosted copies), web proxy cache, browser cache or archived page
  bodies for the 16 November 2026 injection. Indicators from Report URI and
  BleepingComputer. Untested against the original samples.
*/
rule CT_Optimizely_ProjectJS_Injection_Loader_Nov2026
{
  meta:
    description = "Loader injected into Optimizely Project JavaScript: payload host in clear text or base64 (atob variant)"
    author = "Cyber-Threat.net Hunt Lab"
    date = "2026-11-17"
    reference = "https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/"
  strings:
    $host = "1688360.cc" ascii wide nocase
    $host_b64 = "1688360.cc" base64
    $ws = "webshell.lol" ascii wide nocase
    $ws_b64 = "webshell.lol" base64
    $atob = "atob(" ascii
    $pjs = "projectJS" ascii
  condition:
    filesize < 5MB and ($host or $ws or (($host_b64 or $ws_b64) and $atob) or ($pjs and ($host_b64 or $ws_b64)))
}

rule CT_Optimizely_Injection_Payload_Markers_Nov2026
{
  meta:
    description = "Markers of the track.js payload or its inline fallback copy (address swapper, skimmer, iOS loader)"
    author = "Cyber-Threat.net Hunt Lab"
    date = "2026-11-17"
    reference = "https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/"
  strings:
    $k7 = "window._k7" ascii
    $k7b = "window.__k7b" ascii
    $chan = "02111110" ascii
    $tele = "BIGNIAO" ascii
    $card = "card.php" ascii
    $hit = "hit.php" ascii
    $r1 = "5vobauua3ojpklx.icu" ascii nocase
    $r2 = "eil786npto9u5bq.icu" ascii nocase
  condition:
    filesize < 5MB and (($k7 or $k7b) or ($chan and ($r1 or $r2)) or $tele or (($card or $hit) and ($k7 or $k7b or $r1 or $r2)))
}
