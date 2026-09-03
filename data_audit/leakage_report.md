# Auditoria de vazamento — corpus do RAG × test sets

> Gerado por `data_audit/check_leakage.py` (shingle_k=8, near_threshold=0.8, report_threshold=0.5).
> Corpus: `/home/luis.carvalho/all_data.parquet`

**Este relatório documenta; não corrige nada.** Nenhum dataset foi alterado.

## Como ler

Os dois lados têm granularidades diferentes — doc do corpus tem mediana de **199 chars** (trecho/função), contrato de teste tem mediana de **~15.000** (arquivo inteiro). Por isso:

- **Igualdade de hash** é praticamente vazia aqui e vai dar ~0 mesmo havendo vazamento. Está no relatório porque foi pedida, não porque decide a questão.
- **Contenção** (`|shingles(doc) ∩ shingles(contrato)| / |shingles(doc)|`) é a medida que importa: mede quanto de um trecho do corpus está dentro de um contrato de teste — a forma de vazamento que de fato ameaça o experimento, porque é o retriever devolvendo ao Detector um pedaço do próprio contrato sob análise.
- **Jaccard** fica baixo por construção (trecho pequeno × arquivo grande); está registrado só para deixar a visão simétrica no papel.

⚠️ Um casamento pode ser **boilerplate** (OpenZeppelin, SafeMath, ERC20), que é compartilhado por construção e não é contaminação em nenhum sentido útil. O texto casado é exportado em `leakage_matches.csv` para julgamento humano. Casamentos longos são os menos plausivelmente boilerplate.

---
## gervais_dataset (70 linhas — test set configurado hoje)

- Contratos no test set: **70**
- Documentos no corpus: **27714**
- Documentos do corpus curtos demais para avaliar (< k tokens): **776**

### 1. Igualdade exata de hash (sha256)

- Docs do corpus com sha256 **idêntico** a um contrato de teste (código bruto): **0**
- Idem, após normalização (sem comentários, espaços colapsados): **0**

> Este número é esperado ser ~0 e **não deve ser lido como ausência de vazamento**: doc do corpus tem mediana de 199 chars e contrato de teste ~15.000. Ver a seção de contenção abaixo.

### 2. Contenção (a medida que carrega o sinal)

| Nível | Pares (doc do corpus × contrato) | Contratos de teste afetados |
|---|---:|---:|
| `EXACT_CONTAINMENT` — o doc do corpus ocorre **literalmente** dentro do contrato | 5487 | 65 (92.9%) |
| `NEAR_DUPLICATE` — contenção ≥ limiar, sem casamento literal | 12634 | 56 (80.0%) |
| `PARTIAL` — contenção acima do piso de reporte | 26251 | — |
| **Qualquer nível** | **44372** | **69 (98.6%)** |

**dataset_index afetados (69):** `[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70]`

**dataset_index com EXACT_CONTAINMENT (65):** `[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 28, 29, 30, 31, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 54, 55, 56, 57, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70]`

### 3. Casamentos ESPECÍFICOS — os que exigem sua decisão

`match_breadth` = em quantos contratos de teste **distintos** aquele doc do corpus aparece. Breadth alto = biblioteca compartilhada (Uniswap `mint`/`burn`, Compound `getPriorVotes`, ERC20) — presente em milhares de contratos, **não é contaminação em nenhum sentido útil**. Breadth **= 1** é a forma perigosa: código específico daquele contrato, sentado no corpus de retrieval.

- Casamentos com `breadth == 1` e tier ≥ NEAR_DUPLICATE: **156** pares brutos → **55 trechos distintos**, atingindo **15** contratos de teste

> O corpus contém **documentos duplicados** (o mesmo trecho armazenado várias vezes), então a tabela abaixo mostra um trecho distinto por linha; a contagem de pares brutos acima é maior por causa dessas repetições.

| corpus_row | chars | contenção | tier | dataset_index | rótulo GT do teste | trecho |
|---:|---:|---:|---|---:|---|---|
| 3408 | 5856 | 0.85 | NEAR_DUPLICATE | 6 | on-chain oracle manipulation | `function getTokenConfig(uint i) public view returns (TokenConfig memory) { require(i < numTokens, "token confi…` |
| 3210 | 5705 | 0.85 | NEAR_DUPLICATE | 6 | on-chain oracle manipulation | `function getTokenConfig(uint i) public view returns (TokenConfig memory) { require(i < numTokens, "token confi…` |
| 3225 | 808 | 0.93 | NEAR_DUPLICATE | 6 | on-chain oracle manipulation | `function pokeWindowValues(TokenConfig memory config) internal returns (uint, uint, uint) { bytes32 symbolHash …` |
| 3584 | 781 | 1.00 | EXACT_CONTAINMENT | 63 | absence of code logic or sanity check | `function getEstimatedMarginDetails( uint256 leverageAmount, uint256 loanTokenSent, uint256 collateralTokenSent…` |
| 3224 | 507 | 0.86 | NEAR_DUPLICATE | 6 | on-chain oracle manipulation | `function postPriceInternal(string memory symbol, uint ethPrice) internal { TokenConfig memory config = getToke…` |
| 3500 | 401 | 0.91 | NEAR_DUPLICATE | 20 | token standard incompatibility | `function transferFrom(address from, address to, uint256 value) public validRecipient(to) override returns (boo…` |
| 3613 | 392 | 1.00 | EXACT_CONTAINMENT | 20 | token standard incompatibility | `function transferFrom(address from, address to, uint256 value) public validRecipient(to) returns (bool) { _all…` |
| 4130 | 295 | 1.00 | EXACT_CONTAINMENT | 64 | absence of code logic or sanity check | `function transferFrom(address _from, address _to, uint _value) public whenNotPaused { require(!isBlackListed[_…` |
| 3501 | 284 | 0.85 | NEAR_DUPLICATE | 20 | token standard incompatibility | `function increaseAllowance(address spender, uint256 addedValue) public override returns (bool) { _allowedFragm…` |
| 11929 | 274 | 0.86 | NEAR_DUPLICATE | 63 | absence of code logic or sanity check | `function MUL19(int256 a, int256 b) internal pure returns (int256) { if (a == 0) { return 0; } require(!(a == -…` |
| 14174 | 262 | 0.90 | NEAR_DUPLICATE | 63 | absence of code logic or sanity check | `function mul(int256 a, int256 b) internal pure returns (int256) { if (a == 0) { return 0; } require(!(a == -1 …` |
| 3222 | 260 | 0.80 | NEAR_DUPLICATE | 6 | on-chain oracle manipulation | `function getTokenConfigByCToken(address sToken) public view returns (TokenConfig memory) { uint index = getCTo…` |
| 4126 | 259 | 1.00 | EXACT_CONTAINMENT | 64 | absence of code logic or sanity check | `function transfer(address _to, uint _value) public whenNotPaused { require(!isBlackListed[msg.sender]); if (de…` |
| 3984 | 248 | 1.00 | EXACT_CONTAINMENT | 55 | locked or frozen tokens | `function rewardPerToken() public view returns (uint256) { if (totalSupply() == 0) { return rewardPerTokenStore…` |
| 2954 | 247 | 0.81 | NEAR_DUPLICATE | 55 | locked or frozen tokens | `function rewardPerToken() public view returns (uint256) { if (block.number == 0) { return rewardPerTokenStored…` |
| 4134 | 244 | 1.00 | EXACT_CONTAINMENT | 64 | absence of code logic or sanity check | `function approve(address _spender, uint _value) public onlyPayloadSize(2 * 32) { if (deprecated) { return Upgr…` |
| 4115 | 234 | 0.87 | NEAR_DUPLICATE | 64 | absence of code logic or sanity check | `function approve(address _spender, uint _value) public onlyPayloadSize(2 * 32) { require(!((_value != 0) && (a…` |
| 14664 | 234 | 0.89 | NEAR_DUPLICATE | 46 | on-chain oracle manipulation | `function mulUInt(uint a, uint b) internal pure returns (MathError, uint) { if (a == 0) { return (MathError.NO_…` |
| 11930 | 232 | 0.84 | NEAR_DUPLICATE | 63 | absence of code logic or sanity check | `function DIV393(int256 a, int256 b) internal pure returns (int256) { require(b != 0, "SignedSafeMath: division…` |
| 4137 | 231 | 0.80 | NEAR_DUPLICATE | 64 | absence of code logic or sanity check | `function allowance(address _owner, address _spender) public view returns (uint remaining) { if (deprecated) { …` |

### 4. Maiores casamentos (para julgamento manual)

Ordenados pelo tamanho do doc do corpus — casamentos longos são os que menos plausivelmente são boilerplate.

| corpus_row | chars | contenção | tier | breadth | dataset_index | rótulo GT do teste |
|---:|---:|---:|---|---:|---:|---|
| 3400 | 5856 | 0.85 | NEAR_DUPLICATE | 1 | 6 | on-chain oracle manipulation |
| 3207 | 5705 | 0.85 | NEAR_DUPLICATE | 1 | 6 | on-chain oracle manipulation |
| 13290 | 5476 | 0.99 | NEAR_DUPLICATE | 1 | 6 | on-chain oracle manipulation |
| 2750 | 1683 | 0.93 | NEAR_DUPLICATE | 2 | 60 | reentrancy |
| 2750 | 1683 | 0.93 | NEAR_DUPLICATE | 2 | 59 | flash liquidity borrow, purchase, mint or deposit |
| 2740 | 1068 | 1.00 | EXACT_CONTAINMENT | 2 | 60 | reentrancy |
| 2741 | 1068 | 1.00 | EXACT_CONTAINMENT | 2 | 59 | flash liquidity borrow, purchase, mint or deposit |
| 2748 | 1020 | 0.89 | NEAR_DUPLICATE | 2 | 59 | flash liquidity borrow, purchase, mint or deposit |
| 2748 | 1020 | 0.89 | NEAR_DUPLICATE | 2 | 60 | reentrancy |
| 3225 | 808 | 0.93 | NEAR_DUPLICATE | 1 | 6 | on-chain oracle manipulation |
| 3584 | 781 | 1.00 | EXACT_CONTAINMENT | 1 | 63 | absence of code logic or sanity check |
| 2749 | 775 | 1.00 | EXACT_CONTAINMENT | 2 | 60 | reentrancy |
| 2749 | 775 | 1.00 | EXACT_CONTAINMENT | 2 | 59 | flash liquidity borrow, purchase, mint or deposit |
| 7409 | 748 | 0.51 | PARTIAL | 3 | 67 | fake tokens |
| 7409 | 748 | 0.51 | PARTIAL | 3 | 36 | other unsafe defi protocol dependency |


---

## web3bugs_testset_human (268 — base da run de referência 28-07)

- Contratos no test set: **268**
- Documentos no corpus: **27714**
- Documentos do corpus curtos demais para avaliar (< k tokens): **776**

### 1. Igualdade exata de hash (sha256)

- Docs do corpus com sha256 **idêntico** a um contrato de teste (código bruto): **0**
- Idem, após normalização (sem comentários, espaços colapsados): **0**

> Este número é esperado ser ~0 e **não deve ser lido como ausência de vazamento**: doc do corpus tem mediana de 199 chars e contrato de teste ~15.000. Ver a seção de contenção abaixo.

### 2. Contenção (a medida que carrega o sinal)

| Nível | Pares (doc do corpus × contrato) | Contratos de teste afetados |
|---|---:|---:|
| `EXACT_CONTAINMENT` — o doc do corpus ocorre **literalmente** dentro do contrato | 873 | 192 (71.6%) |
| `NEAR_DUPLICATE` — contenção ≥ limiar, sem casamento literal | 262 | 42 (15.7%) |
| `PARTIAL` — contenção acima do piso de reporte | 1933 | — |
| **Qualquer nível** | **3068** | **228 (85.1%)** |

**dataset_index afetados (228):** `[1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 14, 16, 17, 18, 19, 20, 21, 23, 24, 26, 27, 28, 29, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 77, 78, 79, 80, 86, 91, 92, 93, 94, 95, 96, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 208, 209, 210, 211, 213, 217, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 253, 254, 255, 256, 259, 260, 261, 262, 263, 264, 265, 266]`

**dataset_index com EXACT_CONTAINMENT (192):** `[1, 2, 3, 4, 5, 6, 10, 11, 12, 16, 18, 19, 20, 21, 23, 24, 26, 29, 31, 32, 33, 34, 35, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 56, 57, 58, 62, 63, 64, 65, 66, 69, 77, 78, 79, 80, 91, 92, 93, 94, 95, 96, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 196, 197, 200, 202, 203, 204, 205, 208, 209, 210, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 234, 235, 236, 237, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 250, 251, 254, 255, 256, 259, 260, 261, 262, 263, 264, 265, 266]`

### 3. Casamentos ESPECÍFICOS — os que exigem sua decisão

`match_breadth` = em quantos contratos de teste **distintos** aquele doc do corpus aparece. Breadth alto = biblioteca compartilhada (Uniswap `mint`/`burn`, Compound `getPriorVotes`, ERC20) — presente em milhares de contratos, **não é contaminação em nenhum sentido útil**. Breadth **= 1** é a forma perigosa: código específico daquele contrato, sentado no corpus de retrieval.

- Casamentos com `breadth == 1` e tier ≥ NEAR_DUPLICATE: **36** pares brutos → **25 trechos distintos**, atingindo **13** contratos de teste

> O corpus contém **documentos duplicados** (o mesmo trecho armazenado várias vezes), então a tabela abaixo mostra um trecho distinto por linha; a contagem de pares brutos acima é maior por causa dessas repetições.

| corpus_row | chars | contenção | tier | dataset_index | rótulo GT do teste | trecho |
|---:|---:|---:|---|---:|---|---|
| 2464 | 1100 | 0.96 | NEAR_DUPLICATE | 165 | other coding mistakes | `function exitPool(uint256 _amount) external override virtual noReentry { require(!this.getLock(), "POOL_LOCKED…` |
| 2463 | 1041 | 0.94 | NEAR_DUPLICATE | 165 | other coding mistakes | `function joinPool(uint256 _amount) external override noReentry { require(!this.getLock(), "POOL_LOCKED"); char…` |
| 1996 | 1029 | 0.85 | NEAR_DUPLICATE | 181 | unchecked low level calls | `function borrowFresh(address payable borrower, address payable payee, uint borrowAmount) internal sameBlock { …` |
| 2468 | 742 | 1.00 | NEAR_DUPLICATE | 165 | other coding mistakes | `function calcTokensForAmountExit(uint256 _amount) external view override returns (address[] memory tokens, uin…` |
| 2467 | 739 | 1.00 | NEAR_DUPLICATE | 165 | other coding mistakes | `function calcTokensForAmount(uint256 _amount) external view override returns (address[] memory tokens, uint256…` |
| 13245 | 606 | 0.88 | NEAR_DUPLICATE | 181 | unchecked low level calls | `function borrowBalanceStoredInternal(address account) internal view returns (MathError, uint) { MathError math…` |
| 2465 | 557 | 1.00 | NEAR_DUPLICATE | 165 | other coding mistakes | `function calcOutStandingAnnualizedFee() public view override returns(uint256) { LibBasketStorage.BasketStorage…` |
| 2462 | 412 | 0.90 | NEAR_DUPLICATE | 165 | other coding mistakes | `function removeToken(address _token) external override protectedCall { LibBasketStorage.BasketStorage storage …` |
| 2466 | 356 | 1.00 | NEAR_DUPLICATE | 165 | other coding mistakes | `function chargeOutstandingAnnualizedFee() public override { uint256 outStandingFee = calcOutStandingAnnualized…` |
| 5077 | 320 | 0.97 | NEAR_DUPLICATE | 167 | other coding mistakes | `function SORTTOKENS379(address tokenA, address tokenB) internal pure returns (address token0, address token1) …` |
| 903 | 317 | 0.94 | NEAR_DUPLICATE | 167 | other coding mistakes | `function sortTokens(address tokenA, address tokenB) internal view returns (address token0, address token1) { r…` |
| 3630 | 274 | 0.83 | NEAR_DUPLICATE | 161 | arithmetic | `function mint(address account, uint256 amount) external onlyOwner { require(account != address(0), "ERC20: min…` |
| 3527 | 272 | 0.83 | NEAR_DUPLICATE | 161 | arithmetic | `function mint(address account, uint256 amount) public onlyOwner { require(account != address(0), "ERC20: mint …` |
| 756 | 268 | 0.84 | NEAR_DUPLICATE | 34 | arithmetic | `function supplyTokenTo(uint256 _amount, address to) override external { uint256 shares = _tokenToShares(_amoun…` |
| 21161 | 265 | 1.00 | EXACT_CONTAINMENT | 161 | arithmetic | `function _mint(address account, uint256 amount) internal { require(account != address(0), "ERC20: mint to the …` |
| 10323 | 105 | 0.85 | NEAR_DUPLICATE | 79 | other coding mistakes | `function DELEGATES57(address delegator) external view returns (address) { return _delegates[delegator]; }…` |
| 1779 | 97 | 1.00 | EXACT_CONTAINMENT | 69 | write to arbitrary storage location | `function balanceOf(address account) external view returns (uint256) { return balances[account]; }…` |
| 4216 | 72 | 1.00 | EXACT_CONTAINMENT | 235 | reentrancy | `function depositAll() external { deposit(token.balanceOf(msg.sender)); }…` |
| 3363 | 60 | 1.00 | EXACT_CONTAINMENT | 78 | other unfair or unsafe defi protocol interaction | `function desiredLiquidity() external view returns (uint256);…` |
| 2009 | 46 | 1.00 | NEAR_DUPLICATE | 161 | arithmetic | `mapping(address => uint256) private _balances;…` |

### 4. Maiores casamentos (para julgamento manual)

Ordenados pelo tamanho do doc do corpus — casamentos longos são os que menos plausivelmente são boilerplate.

| corpus_row | chars | contenção | tier | breadth | dataset_index | rótulo GT do teste |
|---:|---:|---:|---|---:|---:|---|
| 3364 | 1187 | 0.69 | PARTIAL | 1 | 78 | other unfair or unsafe defi protocol interaction |
| 2464 | 1100 | 0.96 | NEAR_DUPLICATE | 1 | 165 | other coding mistakes |
| 2463 | 1041 | 0.94 | NEAR_DUPLICATE | 1 | 165 | other coding mistakes |
| 1996 | 1029 | 0.85 | NEAR_DUPLICATE | 1 | 181 | unchecked low level calls |
| 13287 | 879 | 0.77 | PARTIAL | 1 | 78 | other unfair or unsafe defi protocol interaction |
| 13469 | 869 | 0.77 | PARTIAL | 1 | 78 | other unfair or unsafe defi protocol interaction |
| 10327 | 815 | 0.72 | PARTIAL | 2 | 69 | write to arbitrary storage location |
| 10327 | 815 | 0.92 | NEAR_DUPLICATE | 2 | 79 | other coding mistakes |
| 13316 | 806 | 0.71 | PARTIAL | 2 | 69 | write to arbitrary storage location |
| 13316 | 806 | 0.96 | NEAR_DUPLICATE | 2 | 79 | other coding mistakes |
| 3739 | 804 | 0.90 | NEAR_DUPLICATE | 2 | 79 | other coding mistakes |
| 3740 | 804 | 0.75 | PARTIAL | 2 | 69 | write to arbitrary storage location |
| 13468 | 774 | 0.71 | PARTIAL | 1 | 78 | other unfair or unsafe defi protocol interaction |
| 2468 | 742 | 1.00 | NEAR_DUPLICATE | 1 | 165 | other coding mistakes |
| 2467 | 739 | 1.00 | NEAR_DUPLICATE | 1 | 165 | other coding mistakes |

