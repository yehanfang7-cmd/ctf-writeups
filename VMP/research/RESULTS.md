# VMP 實驗執行記錄

執行時間：2026-11-24T01:16:04.503650+00:00。

環境：Python 3.11.9，Windows-10-10.0.26200-SP0。

本次產物：`generated/runs/20261124T011400412786Z`。

實驗產物壓縮包：`generated/runs/20261124T011400412786Z/research_bundle.zip`。

來源 commit：`d2b26d66db59e341f179c7e326246d28c4d25491`；下載材料：20 個檔案。

| 步驟 | 結果 | 秒數 |
|---|---|---:|
| xor | 通過 | 1.71 |
| multipath | 通過 | 10.00 |
| mba | 通過 | 2.13 |
| test_replay | 通過 | 0.21 |
| test_merge | 通過 | 0.44 |
| test_pipeline | 通過 | 0.40 |
| native | 通過 | 0.34 |
| robustness | 通過 | 28.73 |

本輪可靠性研究、消融及上游結果比較見 [研究報告](REPORT.md)。


## 新增 MBA 案例

sample3 重播 25085 條指令；低 8 位元語義 SMT 等價檢查為 UNSAT。
本機執行全部 65536 組 8 位元輸入及 75 組高位元檢查通過；LLVM IR 指令數 144 → 47。

結果契約：`low8((x XOR 92) + y)`；尚未聲稱自動合成出最短公式。


## 還原函式的本機執行結果

LLVM IR 經 O3 最佳化後編譯為本機程式碼，以 ctypes 呼叫，與獨立的 Python 機器語義模型比對。指令數含 ret，不代表執行效能倍數。

| 案例 | 通過輸入組數 | IR 指令數 | 最佳化後 IR 指令數 | 目的檔位元組 |
|---|---:|---:|---:|---:|
| sample2 | 10100 | 2 | 2 | 600 |
| sample4 | 10100 | 262 | 10 | 624 |
| sample5 | 10356 | 155 | 6 | 616 |
| sample6 | 10356 | 205 | 10 | 624 |

原生編譯流程依據 [llvmlite 官方範例](https://llvmlite.readthedocs.io/en/v0.46.0/user-guide/binding/examples.html) 與 [最佳化 API](https://llvmlite.readthedocs.io/en/v0.46.0/user-guide/binding/optimization-passes.html)。


## 個案驗證輸出

### xor

```text
trace SHA256: 735c076fdaf56cbdd6b80e0a66d88c76479f258faaf8bdaff1bec7662a63f443
instructions replayed: 12462
recorded result (x=1, y=2): 3
concrete snapshot synchronizations: registers=20, memory=1221
undefined AF snapshot corrections: 5
recovered expression: (bvxor x y)
SMT: recovered != (x XOR y) is UNSAT, for 32-bit x/y
edge/random evaluations: 1088 passed (raw and synthesized ASTs)
scope: recorded pure-function trace; no new native execution or whole-EXE rebuild
```

### sample4

```text
== sample4: int secret(int x, int y) { return x >= y ? x : y; }
trace 1: inputs x=0x1 y=0x2, 17986 instructions, syncs reg=15 mem=1528
  stale symbolic flags dropped: af=10, of=1, pf=2, sf=2; PUSHFQ undefined-bit corrections: af=8
  branch sites: ['0x8ba706']; non-trace program output lines skipped: 0
trace 2: inputs x=0x0 y=0x0, 18068 instructions, syncs reg=12 mem=133
  stale symbolic flags dropped: af=10, of=1, pf=2, sf=2; PUSHFQ undefined-bit corrections: af=9
  branch sites: ['0x8ba706']; non-trace program output lines skipped: 0
virtual branch: 0x8ba706 `mov rax, qword ptr ss:[rbx]` (trace 1 #13952, trace 2 #13952)
branch address values: 0x7ffcb909bf38 (trace 1), 0x7ffcb909bf30 (other side); exactly two feasible
trace 2 condition == NOT trace 1 condition: proved
trace 1 condition, z3-simplified for display: (= (bvnot (bvor (bvor (bvnot (bvor (concat (_ bv4 57) (ite (or (= (= ((_ extract 31 31) x) (_ bv0 1)) (= ((_ extract 31 31) y) (_ bv0 1))) (= (= ((_ extract 31 31) x) (_ bv0 1)) (= ((_ extract 31 31) (bvadd (bvnot x) y)) (_ bv1 1)))) (_ bv1 1) (_ bv0 1)) (_ bv0 3)) (concat (_ bv4 57) ((_ extract 31 31) (bvadd (bvnot x) y)) (_ bv0 3)))) (bvnot (bvor (concat (_ bv144115188075855867 57) (ite (or (= ( ...
each path == C source under its own condition: proved
SMT: merged != C source is UNSAT, for 32-bit x/y
edge/random evaluations: 1031 passed
LLVM IR: 261 instructions (unoptimized; optionally run `opt -S -O3`)
scope: two recorded traces of one binary; no new native execution or whole-EXE rebuild
```

### sample5

```text
== sample5: int secret(int x, int y) { return x + y == 1001 ? x + 1 : y - 1; }
trace 1: inputs x=0x4 y=0x5, 16164 instructions, syncs reg=18 mem=1525
  stale symbolic flags dropped: af=6, cf=2, of=22, pf=32, sf=32; PUSHFQ undefined-bit corrections: af=5
  branch sites: ['0x85bbbe']; non-trace program output lines skipped: 0
trace 2: inputs x=0x3e8 y=0x1, 15758 instructions, syncs reg=10 mem=137
  stale symbolic flags dropped: af=5, cf=2, of=12, pf=29, sf=29; PUSHFQ undefined-bit corrections: af=2
  branch sites: ['0x85bbbe']; non-trace program output lines skipped: 3
virtual branch: 0x85bbbe `mov rax, qword ptr ss:[rdx]` (trace 1 #11870, trace 2 #11870)
branch address values: 0x7fffffffe098 (trace 1), 0x7fffffffe090 (other side); exactly two feasible
trace 2 condition == NOT trace 1 condition: proved
trace 1 condition, z3-simplified for display: (not (= (bvnot (bvadd (_ bv1001 32) (bvnot (bvadd y x)))) (_ bv0 32)))
each path == C source under its own condition: proved
SMT: merged != C source is UNSAT, for 32-bit x/y
edge/random evaluations: 1032 passed
LLVM IR: 154 instructions (unoptimized; optionally run `opt -S -O3`)
scope: two recorded traces of one binary; no new native execution or whole-EXE rebuild
```

### sample6

```text
== sample6: unsigned secret(unsigned x, unsigned y) { return x + y < 1234 ? x + 1 : y - 1; }
trace 1: inputs x=0x1 y=0x2, 14172 instructions, syncs reg=18 mem=1506
  stale symbolic flags dropped: af=14, of=14, pf=8, sf=8; PUSHFQ undefined-bit corrections: none
  branch sites: ['0x8a5bb1']; non-trace program output lines skipped: 0
trace 2: inputs x=0x1 y=0x4d8, 14560 instructions, syncs reg=15 mem=159
  stale symbolic flags dropped: af=17, of=30, pf=11, sf=11; PUSHFQ undefined-bit corrections: none
  branch sites: ['0x8a5bb1']; non-trace program output lines skipped: 0
virtual branch: 0x8a5bb1 `mov rbx, qword ptr ss:[r9]` (trace 1 #10725, trace 2 #10725)
branch address values: 0x7ffd76579b40 (trace 1), 0x7ffd76579b48 (other side); exactly two feasible
trace 2 condition == NOT trace 1 condition: proved
trace 1 condition, z3-simplified for display: (not (and (or (= ((_ extract 31 31) (bvadd y x)) (_ bv1 1)) (= (= ((_ extract 31 31) (bvadd y x)) (_ bv0 1)) (= ((_ extract 31 31) (bvadd (_ bv1233 32) (bvnot (bvadd y x)))) (_ bv1 1)))) (not (= (bvnot (bvadd (_ bv1233 32) (bvnot (bvadd y x)))) (_ bv0 32)))))
each path == C source under its own condition: proved
SMT: merged != C source is UNSAT, for 32-bit x/y
edge/random evaluations: 1032 passed
LLVM IR: 204 instructions (unoptimized; optionally run `opt -S -O3`)
scope: two recorded traces of one binary; no new native execution or whole-EXE rebuild
```

## 解讀範圍

結果來自公開 trace 的符號重播。原生執行階段執行的是還原後的函式；下載的受保護 ELF 未執行，未自行加上 VMP 保護、錄製新 trace 或重建整個 EXE。
SMT 結果針對工具建立的 32 位元機器語義模型；不代表原始 C 的有號溢位具有已定義行為。
回歸測試使用合成符號表達式；個案還原使用本研究目錄下載的資料。
