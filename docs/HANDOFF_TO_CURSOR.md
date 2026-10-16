# 太鼓 Android → Cursor／Grok 4.7 交接

狀態：依使用者要求 **PAUSED_FOR_HANDOFF**。沒有啟動 Cursor／Grok，沒有排下一個修復批次。接手施工者沿用同一位 Cursor／Grok 4.7，GPT 6.1 Sol 分段審查；須等使用者核對及正式交接才恢復施工。交接不代表移植完成。

## 1. 位置、Git 與可重現 checkpoint

- 原始碼 `R = C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android`。
- 協調／使用者輸出 `C = C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android-coordination`。
- D2R 參考 `D = C:/Users/aa223/Documents/Codex/2026-10-12/10m-10s-jhaizhou-ops-d2r-mobile`，整個目錄唯讀，不在該處跑 Git、build、產生 pycache 或覆寫來源。
- 獨立 Git common database：`C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android.git`；此 checkout gitdir 為其 `worktrees/taiko-android`。它不借用 D2R Git。
- 分支 `codex/taiko-android`；沒有 remote／push。
- **最後已驗證來源 HEAD：a2c9208e6fa78bf679c05a9348509327c3d8ca20**。前一個有限指令列／索引 checkpoint 為 `23ce25ffcd91c85dc7ff2e6e6ceec4d8ad436571`。
- 本文件另作文件提交。交接完成後的最終 Git HEAD、文件 SHA 與最終未提交狀態記在 `C/outputs/taiko-cursor-handoff/HANDOFF_RECEIPT.json`，避免在文件中寫入自身 commit hash 形成循環。
- 封存來源 `R/.local/toolsets/taiko-handoff-054/manifest.json`，SHA256 `6d2ae9eff9afd90ea6b6d69df28d22c65c18a65f27d75cee2eeaa83f6124f46e`，17 檔包含新增 Python／ABI header 依賴。**它是已驗證來源快照，尚未以它完成三模組匯入，不能當啟動授權。**
- 最終白名單提交只含相容層來源／自製測試／文件；沒有遊戲、歌曲、譜面、金鑰或原始 shader bytes。禁止 `git add .`、推送或盲合 D2R。

未提交內容：版控可見僅 `new.local/`；保留其 038 封包，不移動、不刪除。`.local/` 是忽略的本機證據／工具／候選／建置產物／本地原版抽出資料，不是可直接匯入的變更集合。下列私有候選特別列明，勿把忽略狀態當成已提交或已通過。

| 位置 | 採用狀態 |
| --- | --- |
| `new.local/entry-guard-allocation-038/` | 兩個 set hoist 已審閱、整合至 23ce25f，後續 626／641／690 回歸及 041 獨審保留同一 reference helper。原封存 READY 是當時狀態，不代表現在有人在寫。 |
| `.local/entry-index-041/` | 已獨審整合；原 staged SHA `a0593da349141afcd4916f765885e7faa0c6111cb8d8279adbe66289fb2c2ded` 不是整合後檔案 SHA。 |
| `.local/diagabort-ticket-reception-039/`、`.local/readwait-composition-043/`、`.local/diagabort-pub-canonical-052/` | 039 runtime／040 epilogue／052 source-only publication proof 已接收、獨審、整合至來源 checkpoint。原 seals 不改寫。 |
| `.local/diagabort-publication-fix-048/`、其 `canonical-048b/` | **拒絕／重現用**。048/ff57 仍會接受 restored-head 反例；不得採用其 helper。048b 只有 RED 測試，沒有 canonical 實作。 |
| `.local/main-nested-053/` | **未獨審、未整合**，接手第一個審查候選；不可先作正式啟動授權。 |

038 的原移動操作曾被自動核准審查擋下，只回報 `blocked by policy`；已保留原位置及 seal／差分驗證。不要以另一種刪移手段繞過。未丟失封包，也不需為目錄名稱阻擋交接。

## 2. 太鼓 1.1.1 身分與原始內容

原始 ExeFS：`D/games/taiko-extract/ExeFS`；完整 source pin 在 `dm/platform/android/taiko_bringup.cpp`、`dm/tools/taiko_content.py`。Program ID `01002460135A4000`，Unity `2020.3.26f1`，IL2CPP metadata 27。

| 檔案 | bytes | SHA256 |
| --- | ---: | --- |
| main | 38127530 | f1313fe0d6cd4a024e53d8a283434448bacea453b02f37b75b18bfe281d0fcff |
| sdk | 5989236 | 2a89fa1c0e677710e89ed29b578162affef530a0c9b8c93cda15d50a57a20d28 |
| subsdk0 | 3385425 | f38d30e8241ee208cbf3090f44613e328af517ad199eb5985619416bb2cbcb55 |
| rtld | 7132 | 8e08c8cf2e4d6b39d69643af10ce765d39c06860878224c68f8cafc45a2636aa |
| main.npdm | 1572 | afd3aade95cbcc607759eb677b67082193719a701a5b0cc8ed78ac33b5c65150 |

main build ID `4541b79257635ce79105b3ba59e4808500000000000000000000000000000000`；sdk `357efc198e728cb5d55265aff304f03cfc9cc0e3000000000000000000000000`；subsdk0 `a8cb97803f7f442a3b6cce1c7cd4ee4a78b7def3000000000000000000000000`。

容器 `D/taiko.xci`，3829707776 bytes，SHA `c129a9d5942b1a4651d55fc7c10e6cf757ee1a9c8472928c8c2f6e9bef32fc7d`。`R/.local/exefs-version-probe-002/manifest.json` SHA `63169bbf9ce848812f704d9e405f64988872b4a12036a24e3b63c0f5e74bfe68` 保存 fresh base／patch 五檔對照：現有五檔組合唯一吻合提供容器的 **patch 1.1.1**；main／NPDM 排除 base。raw NCA 與 CNMT 整體 hash mismatch 保留，沒有宣稱 publisher 簽章驗證。

原版內容只在本機使用。交給外部提示詞只能是必要的來源身分、錯誤與經清理的任務資料，不能送 ROM／歌曲／譜面／keys／原始 shader bytes。不要提交 `.local` 原版抽出資料。

## 3. 最新完整預檢：三者都已終止

| 模組 | 最新完整結果／來源 | 正式證據 |
| --- | --- | --- |
| main | **CLOSED／REJECTED `0x28c134: nested/overlapping exclusive window`**；main014，frozen027 manifest `37a2ec3c5a3498f7ad7573d5ae12b17e95e10f09e57e8276596615db77bf2925` | `.local/main-preflight-014.log`、`main-preflight-014/import.json`、`main-preflight-014-survey/official-result.json`；inputs/output/function unchanged=true。舊 28bd84 與同函式後續排列已跨過。 |
| sdk | **CLOSED／REJECTED `0x373b5c: host gate in exclusive window starting 0x373b50`**；SDK022，frozen026 manifest `779c6941841b73e292107b438c36997ea8047438984b9e1e07211326cf3d588e` | `.local/sdk-preflight-022.log`、`sdk-preflight-022-survey/official-result.json`；三項 unchanged=true。之後本地修正已整合，但尚未用最終來源完整重跑。 |
| subsdk0 | **CLOSED／PREPARED**；preflight022、同 frozen026 | `.local/subsdk0-preflight-022-survey/official-result.json` ORIGINAL_SUCCESS／inputs unchanged；原版 NOT_RUN。 |

可沿用的比較套件：`.local/subsdk0-preflight-022/subsdk0.dmag`，9504544 bytes，SHA `7478b05cffd6f4e6d171af0ea205f2964524ad633e348af5c3e5a5e99ddc76ab`。image 8240032 bytes／SHA `3c8c1dd807f7e82585dd3e60a9e670525339c9f45feee9ab62ace6419c53cce3`，8293 roots／22725 gates／33548 sites。已有正式 C++ decoder 與九個負例；**只有 decode，沒有 Process.load／mapping／entry 執行**。

最終 provider 仍須三模組以同一受審來源重產／重驗；不可把不同 frozen 版本拼成啟動套件。舊 subsdk0 bytes 可比較，不能免掉新來源的一致性驗證。frozen009 有 ordinary-index 安全回歸，永久禁止作授權來源；`fixture(64),0x3E0` 原拒絕保留並通過回歸。

沒有尚在執行的完整匯入。歷史工具 session（非 OS PID）：main014 `10422`、main013 `7078`、SDK022 `6646`、sub022 `30670` 均 CLOSED。當時未保存的 OS PID 不補造。舊 progress.json 停留在最後採樣不是 RUNNING 權威，以 official-result 為準。

## 4. 初始化、依賴與 provider

載入／符號順序是 **main、subsdk0、sdk**（索引 0／1／2），strong imports 原版清單為 1123／655／8。它與 constructor 執行順序不同。provider 要完整 source/build、NPDM、rtld、三個受審 DMAMOD02 package、checked SP、callback audit、資源樹及 own compiled registry 身分；使用 `gen_taiko_pins.py`，不能使用 D2R stock 固定位址或其來源 pin。

`taiko_startup_plan()` 已依該版 SDK Start `0x2dbb80..0x2dbbf0` 固定：

1. SDK `_init_libc0 0x5691f0`。
2. SDK `nnosInitialize 0x37f160`。
3. `taiko_host_loader_ready`，只接替缺席 rtld callback A 的 exception-ready store。
4. SDK `_init_libc1 0x5691f8`。
5. SDK `nninitInitializeSdkModule 0x2dbaf0`。
6. main `nninitStartup 0x300dc0`。
7. SDK `_init_libc2 0x569210`。
8. loader callback B 以 reverse modules 執行 **SDK → subsdk0 → main 的 DT_INIT 各一次**。
9. `taiko_platform_attachment`。
10. main `nnMain 0x300e60`。

`Process::run_initializers` 在呼叫前標記 init_started，拒絕 reentrant／failed 重入；不要再手動跑 initializer 或 DT_INIT_ARRAY 造成雙重初始化。constructor 內原本的 init-array 行為由原版路徑承擔。

`R/.local/taiko_build_pins.cpp` **不存在**，`compiled_taiko_bringup_pins` 仍為未定義 weak，provider=false。真正 SDK／nnMain **NOT_RUN**，原版第一幀 **NOT_OBSERVED**。不能從測試 APK 或合成畫面改寫這些狀態。空的太鼓 shader catalog 保持拒絕未知 shader，沒有偷用 D2R shader。

## 5. 下一個直接阻塞與 053 候選

main 最新拒絕的真 FDE 是 `0x28c0fc..0x28c200`，65 words；可信入口 CFG 選 56，九個尾端清理 words `0x28c1dc..1fc` 未選取。053 作者核對只有一個外部 direct caller，沒有新猜入口。

`.local/main-nested-053/` 候選擴充既有 native_pointer_chain 的精確 sparse allocation/free-list pop 排列，包含 detached CLREX 清理：28 個 words／112 bytes，全四個 load heads 與對應儲存路徑受保護。作者 14 tests、78 CPU executions、31-state monitor graph 及真原版 bounded rewrite 通過；九個 UNKNOWN 不動。**尚未獨審、尚未與當前 039／040／052 來源合併，沒有完整 main 證據。**

- patch SHA `dbb78b287a54a8cec48fb1e8d880a67a4d0ff0693ce6f4cb6ab481169477cf51`。
- 作者 staged exclusive SHA `f2b3aa05240f7f6143403651750b325ea1a32d4256fdf1dba1c42f5be580ef9d`，基底為 23ce25f 的 `b19621d3...`，不能覆寫當前包含共用修正的 exclusive。
- `REPORT.md`、`manifest.json`、`source-facts.json`、`stage-original-proof.json` 保存採用界線。

正式交接後先由 Sol 審這份有限候選，再決定窄合併；不得只為綠燈改負例。可在**封包副本**重現，避免改寫 seal：

```powershell
Set-Location C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android
# cursor-review-053 必須是新目錄；不要覆蓋現有封存。
Copy-Item -LiteralPath .local/main-nested-053 -Destination .local/cursor-review-053 -Recurse
C:/Python311/python.exe -B .local/cursor-review-053/run_tests.py base
C:/Python311/python.exe -B .local/cursor-review-053/run_tests.py stage
C:/Python311/python.exe -B .local/cursor-review-053/original_proof.py base
C:/Python311/python.exe -B .local/cursor-review-053/original_proof.py stage
```

base 的失敗／refusal 是預期負向對照，run_tests base 自身 exit0 不代表其 assertions 全 PASS；讀 JSON／log。不要在原封包上重跑會改寫 evidence 的腳本。

函式指標舊阻塞 `0x56925c BR X3` 是 **已有正確 lowering、缺少 transfer proof recording**，已修並由 SDK021 正式跨過；不要重修。原版 RX 位址不等於合法 callback；defined STT_FUNC／finite targets、source producer、global entry／typed-transfer facts、build／epoch ownership 仍是必要條件。

## 6. WFE 分組與覆蓋界線

已分析的 SDK WFE cohort 是 **已見 17 個正 FDE**，不是全遊戲剩餘總數。037 前為 3 bounded PASS／14 REFUSE；六條有限 metadata rows 後為 **15 PASS／2 REFUSE**，新增 12 個完整 FDE／1273 原版 words。兩個剩餘群是 `37cdb0..37ce8c`（55 words）與 `37cf00..37cff8`（62 words）。039＋040 的 valid-contract proof 對兩者及合併 117 words bounded codegen PASS；不等於已跑過完整 SDK 或全遊戲。

六組：contiguous41-A×2（含最新 SDK gate 所在函式）、sparse41×1、contiguous41-C×3、33×2、40×3、contiguous41-D×1。完整 member／head／source／entry facts 以 `.local/sdk-native-wait-cohort-037/{manifest.json,cohort-final.json,batch-A-proof.json,batch-B-proof.json}` 為準。

獨審重播 12 真 FDE、11432 fixed-bit 負例、473 entry 負例、908 個原 incoming source words、658-state monitor graph；57 raw CPU scenarios。非零 TLR102／pin-state 仍 unsupported，不能偽造成功或清旗。Svc36 以 CLREX-before-host-frame 退休；WFE／重試原字保持。main raw WFE 搜尋為零不代表所有動態／資源／平台路徑都不存在。

先前同型未見原版正例尋找目標二個、找到零個，屬 NOT_FOUND_NOT_EVALUATED；兩個 D2R 原 SDK holdout REFUSED／UNKNOWN 留存，不能改稱跨版本正例 PASS。main19 初評一 PASS／一真 callee FAIL 留存，修復依賴閉合不是盲測全綠。

## 7. 匯入成本與 gate

必要條件：原版 source/build、指令及 code/data role、閉合 reservation／entry、TLS/x18/SP、finite callback domain、W^X／記憶體保護、完整 provider/resource 一致性。不得用任意 RX、跳未知指令、成功 stub、放寬判定窗口或假音訊完成繞過。

已定位策略成本：舊 require_single_entry 對每個 region 全掃 selected instructions；038 將相同 set difference 外提，041 在每次 immutable planner invocation 建 canonical nonfallthrough reverse index，normal fallthrough 查實際 predecessor。保留全部 selected/disconnected sources、BL continuation、metadata-first／原第一個 witness、shared-head 差異與 typed facts；異常回舊 scanner。039 新加兩個 guards 保留舊 scanner。

041 獨立 1560＋2500 差分、mutable-object 跨次 accept→reject→accept、72 regressions 通過。18k source／119 guards 有界 CPU median 2.593750→0.035156s；16k／4000 distinct targets peak 約1019083→1518907 bytes。這些 **不證明完整匯入加速、記憶體適配或遊戲效能**。main013 約4351s 失敗於28bd84；main014 使用不同來源並失敗於不同位置，不能當受控 A/B 速度比較。

main014 30s observer 顯示成本仍包含原版探索、global memory-write audit、whole-text audit、重新 decode 及 planner；不從採樣推估各階段 CPU 比例、剩餘 PC 或 ETA。observer 不改 importer function/input/output。新 052 pins publication 為了獨立 source necessity 會重用 canonical discovery，可能再耗長時間；不能讓 receipt 或 capsule site／改字與否當是否檢查的開關。

## 8. D2R 共用 patch 與必要依賴

D2R 聯絡 thread `01a13ab7-5397-7452-b91b-2f450be60080`。只交換共用機制／必要的乾淨測試；太鼓地址、完整 build 與 startup plan 獨立。以下狀態截至來源 checkpoint：

| 封包／機制 | 狀態與依賴 |
| --- | --- |
| shared-checked-call-001/002、shared-table-proofs-006、shared-native-target-writes-013 | 歷史已交換並整合／回歸；不要重寫 checked-call core。舊 packet 的基底不等於目前 HEAD。 |
| shared-adrp-consumer-025 | 已接收 caller guard，D2R 自驗 RED→GREEN；保留有限 source clobber／producer facts。 |
| shared-native-transfer-031 | 已整合原 native BR proof recording；patch `ac869a...` 的精確 pin 見 READY／manifest。D2R BLR X21 不算同型原版正例。 |
| parent038 native wait platform／native-wait-probe-receiver-019 | 已接收共用 core／platform，太鼓自有21/34b合成實測；不宣稱原版跑過。 |
| shared-svc36-retirement-036 | 我方最小通用 delta，manifest `d973d54022bbef7d8424e4d198aff401e42ce27d0e75e3f1ed05ef830ad14bc5`；D2R 已獨立接收測試。 |
| shared-entry-index-049 | 已交 D2R；manifest `fbec14091296d0342f600a1325b204b80ba0816009b8fdae2d38174becdc2aaf`；對方隔離候選自驗，不能直接覆寫任一工作目錄。 |
| diagabort-ticket-reception-039 | 已接收 parent057 core＋native runtime／required bit1；SOURCE_FREEZE `11297fee55437fa794165ef47fd4a6afed78e3c07135bb0dd68d9ec6411efced`。15來源必須整組，不能只接 matcher 或以 symbol 名稱直接當 noreturn。 |
| readwait-composition-043（040 delta） | 已獨審整合；精確16-byte LDP access／48-byte frame；其餘 native poll／restore 原字不變。 |
| diagabort-publication-fix-048／ff57 | **拒絕**：downflag＋四 receipt keys 刪除，以及 restore-head＋真 site table 移除反例仍可接受。保留 RED，永不採用。 |
| diagabort-pub-canonical-052 | **已接收、獨審、整合**；SOURCE_FREEZE `8e2949fd1832cd99ef71fb25316663b3e02fef842628d6d047a981cc140a8ab1`，patch `c627c0a064f54f1d708dcc571aa594b0f3022f615b73e3f826b1a0bbd5f6bfc8`。必要性先由原始 canonical code roles＋既有 PLT/ticket proof 形成，再核 capsule／receipt。 |

039 必要檔案：`android_diag_abort.py`、`diag_abort_abi.h`、`diag_abort_runtime.h/.cpp`；以及 `android_rewrite.py`、`android_exclusive.py`、`android_import.py`、`module_runtime.h/.cpp`、`kernel_runtime.h/.cpp`、`guest_entry.S`、native CMake、兩個 pins generators。必須連 package required flag、source PLT/GOT/BL coverage、native decoder/load identity、唯一 hidden CLREX-first canonical binding、owned origin／stack/runtime registration、pins generation 一起驗證。bit0 checked-stack 相容性保留。

原039曾被045以 HIGH 拒絕發布；目前由052修正覆蓋。反例 package SHA `2a936d258363e63176b6a14ad5a7a16cda77fb841db4151f37b26e705b39cea4`、結構性 restored head `07a128bd14f42e5f3cd736b7bf89c28cd254ad81ce3755f222f0cff68047f58b` 均在052兩 generators拒絕。legitimate CLREX／fresh LDAXR／unselected RX patterns仍通過；未知 canonical discovery 拒絕，不變成 optional。

D2R 的 importer 另有按完整身分決定的 conditional_switch_windows prelude，太鼓的實際 discover_code 簽章沒有該參數。D2R 接收052須保留自己的可信 module-name/build/source prelude，不能讓 receipt 選視窗，也不能把 D2R windows／固定地址塞進太鼓。D2R 真 main／SDK 是否完成新 publication 重證由對方紀錄；我方沒有宣稱其通過。

跨平台接收曾把 CRLF 改成 LF；收尾已只恢復 unchanged-line 原格式。`R/.local/handoff/line-ending-restoration.json` 證明 normalized bytes／Python AST 含位置完全相同，並 fresh rebuild 出 **相同 APK／ELF bytes**。因此原039／052 raw SHA 與本地 restored raw SHA可能不同；不可用 ignore-space／force patch掩蓋差異，使用記錄重證。

## 9. 建置／回歸與最新產物

工具：`C:/Python311/python.exe -B`，capstone5.0.6／lz4 4.4.5；Unicorn 已在 `R/.local/test-env/Lib/site-packages`。NDK `C:/Users/aa223/AppData/Local/Android/Sdk/ndk/28.2.13676358`，Java `C:/Program Files/Eclipse Adoptium/jdk-21.0.9.10-hotspot`。沒有新增依賴。

```powershell
Set-Location C:/Users/aa223/Documents/Codex/2026-10-16/taiko-android
$env:PYTHONPATH='.local/test-env/Lib/site-packages;dm/verify/android/tests'
C:/Python311/python.exe -B .local/run_available_android_tests.py
C:/Python311/python.exe -B -m unittest discover -s dm/verify/android/tests -p 'test_taiko*.py'
C:/Python311/python.exe -B -m unittest test_android_diag_abort_canonical_obligation test_android_diag_abort_publication test_android_diag_abort_restored_head
C:/Python311/python.exe -B dm/tools/gen_android_kernel.py --ndk C:/Users/aa223/AppData/Local/Android/Sdk/ndk/28.2.13676358 --native-wait-only --check
$env:JAVA_HOME='C:/Program Files/Eclipse Adoptium/jdk-21.0.9.10-hotspot'
$env:PATH=$env:JAVA_HOME+'/bin;'+$env:PATH
./dm/android/gradlew.bat -p dm/android --max-workers=2 --console=plain :app:assembleDebug :app:assembleDebugAndroidTest :app:lintDebug
```

收尾最後回歸：**690 PASS／79.646s**，18 個繼承缺 fixture案例明列排除，不算 PASS；Taiko102＝98PASS／4既有 host compiler SKIP；publication12PASS。Ruff F／Python AST／NDK compile及實際 link檢查通過。LSP工具只顯示 tsc skipped，沒有 Python type analysis，不能寫成已 typecheck。

最新 build：`.local/native-handoff-build-054/`，App/test/lint **PASS16.953s**，1457檔建置期間不變；`source-manifest.json` SHA `3bee21ac85e4c24b293038c2726bdf9c0367c12a44a718af6243a46a10b51674`。之後新增本交接文件屬文件變動，沒有再改 compiled native source。050保留為換行恢復前歷史證據，兩批 binaries相同。

| 檔案（054/build/） | bytes | SHA256 |
| --- | ---: | --- |
| app.apk | 20729756 | 09110be3b882e1df8db965fb486e97161064bc8a7803ea9421aa89e4432230d2 |
| test.apk | 815730 | 64ee035149e00051aa3280c797a9f973dd3d54087f268c5cde4ac9a58559daf4 |
| libd2r_diagnostics.so（stripped） | 6578240 | 61f29c5ff690d910c7ac299efe8d058be9ae0e17f61a3e66bf6d15b6fb6faf67 |
| libd2r_diagnostics-unstripped.so | 34570264 | 743a32af89ee2e6da1c7f03a6b4c18061cc6aa56f88575413e7412fb767b0411 |

`verify_binary.py`／`verify_retirement.py` 實際 PASS：舊243個 registry names/kinds/reasons＋唯一 `__dm_android_diag_abort_v1`＝244個RELATIVE／symbol-index0、零ABS64；新16B hidden entry首CLREX、X4=LR／X5=SP、直接B到hidden handler、無PLT／GOT動態劫持；保留兩個舊typed entries、26 TLS descriptors／14 immutable closure calls、76B034bhelper與50176Bcapsule。這些是靜態 linked ELF及來源／host測試，不是新APK實機。

重建時勿直接覆寫 054 的 build/ 或 accepted manifest；用新輸出目錄／新受審來源快照。普通 Gradle 命令可重建程式，artifact identity須重新記錄。新APK沒有裝到手機，provider仍false。

重現最新完整拒絕的命令（需新 evidence/output 名稱，耗時；本次交接不再啟動）：

```powershell
C:/Python311/python.exe -B .local/import-with-failure-survey-026.py --toolset .local/toolsets/taiko-027 --evidence .local/repro-main014-once-survey --manifest-sha256 37a2ec3c5a3498f7ad7573d5ae12b17e95e10f09e57e8276596615db77bf2925 -- C:/Users/aa223/Documents/Codex/2026-10-12/10m-10s-jhaizhou-ops-d2r-mobile/games/taiko-extract/ExeFS .local/repro-main014-once --modules main --package-version 2 --indirect-policy guarded-host --checked-stack --callback-audit
```

frozen026 的 SDK／subsdk0 同樣 observer，以 `--modules sdk`／`--modules subsdk0`、對應 frozen026 manifest／新輸出名重播歷史結果。當前來源恢復施工後須使用 handoff snapshot 或其已審更新版，先保持三模組同源；不能把歷史拒絕指令當最新來源已測結果。

## 10. 外部基準、實機與裝置排程

官方 Eden0.2.1／embedded1f6734c／versionCode32873047，package `dev.eden.eden_emulator`；APK SHA `befbf70b1a05715811fe092ef9cf71e6f1c1672008a6c5caa31d633e99615668`，signer `7fca26483b2d1b3dc3e6d9bb836e2fee18f09dc644353befd2fce8606bd2a40a`。官方來源／APK身分研究與D2R共用，不重做。

S24原版夏祭りEasy3：選曲→整首→原版FAIL結算12530／良8／可13／不可114／combo3／roll6／gauge3%→正常退出存檔→舊PID10237消失→新PID25742讀回同統計及610coins。證據 `C/outputs/external-taiko-baseline/`，manifest SHA `ce4a753fcc41bdfbc8da74b32762c56b0e71abfc9b59e81edff916c4eb29d69c`。**外部比較基準，不是我們的相容層可玩。**179.969s錄影無音軌，沒有音畫同步／物理輸入延遲／漏擊量測通過證據。

S8外部Eden曾在已宣告Vulkan1.0.3的Mali-G71上觸發Vulkan1.1要求assert／SIGSEGV，沒有原版畫面；這不是自製相容層不支援S8的結論，不因此降低自己的目標。

自製034b雙裝置 synthetic WFE／Svc36：每機Svc36兩次、45/39 layout mutex10／contended4、EVTSTRM true；direct retirement probe STXRstatus1／cell unchanged／prefixVerified true。`C/outputs/svc36-retirement-034/`。它不是 checked-V2原版SDK或nnMain。054只build／靜態查核，沒有新實機測試。

裝置 S8 `ce0317133a9ad0190c`、S24 `R5CX10VFFBA` 最後自有時段都已停 own packages、PID absent、D2R明確ACK釋放；沒有目前租約。原 `.local/native-wait-device-034/*-lease.json` 的 GRANTED是歷史取得快照，不能重用；現態另見 `C/outputs/taiko-cursor-handoff/DEVICE_RELEASE_STATE.json`。未清Eden／D2R app資料、存檔、log或重開機。

app `org.taikocompat.android`／test `.test`；JNI類別／lib保留既有d2r命名只是共用殼，不是D2R啟動授權。未來實機時要與D2R協調新時段、核對APK/ELF/serial，原有runner：

```powershell
C:/Python311/python.exe -B .local/svc36-retirement-034/probe/run.py --help
```

runner實際檔名／lease schema以該封包為準；不能用舊lease直接跑。本次沒有啟動runner、adb或裝置測試。

**Fold7留給使用者日用，不碰它。**已配置的獨立折疊 AVD名 `D2R_Taiko_Fold_API36`：Android36／x86_64／7.6in Foldable／1768×2208／hinge，設定 `C:/Users/aa223/.android/avd/D2R_Taiko_Fold_API36.avd/config.ini`。它這次未啟動；若與D2R共用既有排程，先協調隔離，不清其資料。當前APK只有arm64-v8a，x86_64 AVD的鼓面／posture檢查不能宣稱ARM原版執行。需要適用ABI的正式路徑才能測原版，不用success stub冒充。

同一原版EULA2018-04-01／privacy2020-02-27使用者已反覆授權接受；不要再次詢問這兩份相同條款。

## 11. 程序、所有權與恢復施工界線

全部原生子代理已完成或停止，檔案所有權交回ROOT；沒有持續修改來源的背景工作者。main／SDK／subsdk0匯入、測試、build全部已結束。沒有可接管的長匯入PID；若下一輪新開，保存PID、完整命令、凍結manifest／來源、輸出／observer位置，每30秒觀察，先讀最新official-result，禁止把已失敗程序繼續列RUNNING。

自有 build050 Gradle PID88428、自有 build054 PID44972：已用creation time、唯一taiko build UUID/currentDir與idle狀態核對後逐一停止；未使用全域gradle --stop。別人的Gradle／ADB／Pixel_9 emulator未終止，精確收尾snapshot見 `HANDOFF_RECEIPT.json`。先前觀察的外部程序包括Gradle87784／41900、adb58676、Pixel_9 emulator73056／qemu87580；這些不是授權接管／關閉名單。

接手順序（正式交接後才執行）：Sol獨審053→窄合併及必要回歸→一致來源完整預檢三模組→native decoder／資源樹／own registry／太鼓provider／新App ELF綁定→真正SDK初始化與nnMain→第一幀→選曲→全曲→原版結算→存檔→新程序讀回。新拒絕以完整原版流程定位，不重修已跨過位置。必要共用修正先協調D2R，別各寫同核心。

上下分區鼓面、完整摺疊玩法尚未完成；手機化、低延遲與性能挑戰目標保留，**不作首次原版啟動的額外前置工程**。音訊開始被原版實際呼叫後才確認AudioOut／AudioRenderer及依賴；不放寬原版判定、不假造音訊完成。

交接文件與封包已保存後停工，等待使用者核對及正式交接；整個移植仍未完成。
