# Phase 7C public pilot on testnet4: starts the client (layer1/full-stack.ts), which runs three local
# providers (honest, deletes10, outsources) and a watchtower with fresh keys, over three public relays.
# Each "send at least N sats ... to <addr>" line it prints is paid from the local testnet4 wallet
# utxoref-testnet, once per address. Testnet coins only; mainnet is refused by every entry point.
#
#   powershell -ExecutionPolicy Bypass -File scripts\run-testnet4-pilot.ps1 [-Run run2]
#
# The client runs detached and keeps going after this script ends (the smoke test takes days: Δ = 144
# blocks). Log: C:\BitcoinTestnet\pilot\<Run>\client.log. Results: results\full-stack-onchain-testnet4-<Run>.json.
# A run that reuses an earlier run's party.seed files tops their wallets up. If the client dies, resume
# each flagged bond with BSB_SEED=<client\party.seed> node layer1/enforce.ts --state <Run>\enforce-<slug>.json.
param([string]$Run = 'run1')
$ErrorActionPreference = 'Stop'
$wt  = Split-Path $PSScriptRoot -Parent
$run = "C:\BitcoinTestnet\pilot\$Run"
$bin = "$env:LOCALAPPDATA\Programs\BitcoinCore\bitcoin-31.1\bin"
function btccli { & "$bin\bitcoin-cli.exe" -datadir=C:\BitcoinTestnet @args }
New-Item -ItemType Directory -Force $run | Out-Null

$env:BSB_NETWORK = 'testnet4'; $env:BSB_RPC = 'http://127.0.0.1:48332'
$env:BSB_RPC_COOKIE = 'C:\BitcoinTestnet\testnet4\.cookie'; $env:BSB_CONFS = '3'; $env:BSB_FEE_RATE = '2'
$env:BSB_BOND = "$wt\regtest\target\release\bsb-bond.exe"
if ((btccli getblockchaininfo | ConvertFrom-Json).chain -ne 'testnet4') { throw 'the node on 48332 is not testnet4' }

$log = "$run\client.log"
$argv = @("$wt\layer1\full-stack.ts", '--network', 'testnet4', '--pay', 'onchain',
  '--relays', 'wss://relay.primal.net,wss://relay.snort.social,wss://nostr.mom', '--dir', $run,
  '--epochs', '2', '--epoch-blocks', '12', '--deadline', '9', '--term', '450', '--bond-sats', '20000', '--q', '16',
  '--out', "$wt\results\full-stack-onchain-testnet4-$Run.json")
$p = Start-Process "$env:LOCALAPPDATA\Programs\nodejs\node.exe" -ArgumentList $argv -WorkingDirectory $wt `
  -RedirectStandardOutput $log -RedirectStandardError "$run\client.err.log" -WindowStyle Hidden -PassThru
Set-Content "$run\client.pid" $p.Id
Write-Host "client pid $($p.Id); log $log"

# Fund each address the client asks for, once (client fee wallet, each provider, its payment wallet).
$paid = @{}
while (-not $p.HasExited) {
  if (Test-Path $log) {
    foreach ($m in (Select-String -Path $log -Pattern 'send at least (\d+) sats \(testnet4\) to (tb1\w+); it has (\d+)' -AllMatches).Matches) {
      $sats = [int64]$m.Groups[1].Value; $addr = $m.Groups[2].Value
      if ($paid.ContainsKey($addr)) { continue }
      # A run that reuses a party's keys (same seeds) tops its wallet up instead of refilling it.
      $btc = ('{0:0.00000000}' -f (($sats - [int64]$m.Groups[3].Value + 1000) / 1e8))
      $txid = btccli -rpcwallet=utxoref-testnet -named sendtoaddress address=$addr amount=$btc fee_rate=2
      $paid[$addr] = $txid
      Write-Host "sent $btc tBTC to $addr : $txid"
      Add-Content "$run\funding.log" "$(Get-Date -Format o) $addr $btc $txid"
    }
  }
  if (Test-Path "$run\funding.done") { break }
  Start-Sleep 15
}
Write-Host "funder stopped ($($paid.Count) sends). Client pid $($p.Id), running: $(-not $p.HasExited)"
