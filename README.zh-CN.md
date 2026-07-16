# GPTBots Workspace Extension SDK

[English](./README.md) | **简体中文**

构建一个可接入 GPTBots 工作空间的**第三方扩展应用**。当工作空间用户从**工作空间 → 扩展（Workspace → Extensions）**
页面打开你的应用时，GPTBots 会以一个短时效的签名令牌（`?wsa=<JWT>`）的形式，把该用户的身份移交给你的应用。
本 SDK 将这一次握手封装为几个与框架无关、开箱即用的函数。

两个包：

| 包 | 运行环境 | 用途 |
|---|---|---|
| [`@gptbots/workspace-extension-verify`](./packages/verify) | 你的**后端**（Node） | 校验 `wsa` 令牌 → `WorkspaceIdentity`。零依赖。 |
| [`@gptbots/workspace-extension-sdk`](./packages/browser) | **浏览器** | 读取 / 清除 / 交换 `wsa` 令牌。零依赖。 |

> 校验**密钥永远不会出现在浏览器中**。浏览器只是把令牌发送到*你自己的*后端，由后端完成校验。

## 组织扩展应用

你的应用是一个**组织扩展应用**：由组织的 OWNER/ADMIN 在*空间管理 → 扩展（Space Management → Extensions）*中注册。
它仅对该组织可见，并使用**你的应用自己的密钥**（在注册时仅展示一次）进行签名。由于该密钥为你的应用所独有，
即使轮换或泄露，影响也仅限于你自己的应用。

你只需用该密钥调用 `verifyWsa(token, { secret, audience })`，即可完成握手校验。

## 是否消费身份由你决定

平台负责移交身份；至于是否*使用*它，完全由你决定：

- **`use`（使用）** —— 通过你的后端校验，建立会话，并按 `role` 控制功能权限。
- **`receive-only`（仅接收）** —— 读取身份用于展示 / 埋点，但仍保留你自己的鉴权体系。
- **`ignore`（忽略）** —— 完全不读取（等价于 `auth_mode=none`，即一个普通的外链）。

`verifyWsa` 与 `readHandoffToken` 都是纯函数、无副作用，因此“只接收、不使用”不会带来任何额外成本。

## 安装

```bash
npm i @gptbots/workspace-extension-verify   # 后端
npm i @gptbots/workspace-extension-sdk       # 浏览器
```

## 后端 —— 校验令牌

```ts
import { verifyWsa, WsaVerificationError } from '@gptbots/workspace-extension-verify';

// POST /session/exchange  { wsa }
app.post('/session/exchange', (req, res) => {
  try {
    const identity = verifyWsa(req.body.wsa, {
      secret: process.env.EXTENSION_APP_SECRET,   // 你的应用密钥（注册时仅展示一次）
      audience: 'app.example.com',                 // 你的应用域名 —— 必须与令牌中的 `aud` 相等
      // issuer: 'gptbots-workspace'（默认），leewaySeconds: 30（默认），algorithms: ['HS256']
    });
    // identity = { accountId, role, workspaceId, username?, email?, avatar?, appName?, issuedAt?, expiresAt? }
    const session = createSession(identity);       // 你自己的会话
    res.cookie('sid', session, { httpOnly: true });
    res.json(identity);
  } catch (e) {
    const code = e instanceof WsaVerificationError ? e.code : 'Error';
    res.status(401).json({ code });
  }
});
```

## 浏览器 —— 完成握手

```ts
import { consumeHandoff } from '@gptbots/workspace-extension-sdk';

// 在你的落地页上：
const identity = await consumeHandoff({ exchangeUrl: '/session/exchange' });
// 1) 读取 ?wsa=  2) 将其 POST 到你的后端（由后端校验）
// 3) 从 URL 中清除 ?wsa=  4) 返回身份信息
```

`receive-only` / `ignore` 的应用可以只调用 `readHandoffToken()`，或者什么都不调用。

## 端到端流程

```
工作空间（扩展页面）                        你的应用
──────────────────────────                 ────────
点击应用 ──POST /sign-token──▶ GPTBots
GPTBots 签发一个 5 分钟有效期的 wsa JWT
打开 https://app.example.com/?wsa=<JWT> ─▶ 落地页
                                            consumeHandoff() ─POST /session/exchange {wsa}─▶ 你的后端
                                            你的后端：verifyWsa() → 身份 → 你自己的会话
                                            从 URL 中清除 ?wsa=
```

## 安全须知

- **密钥只能留在后端。** 切勿将校验密钥下发到浏览器。
- **立即清除 `wsa`**（`consumeHandoff` 会自动完成），以免它残留在浏览历史 / Referer 中。
- **短时效** —— 令牌有效期约为 5 分钟；请把它当作一次性的引导凭证，随后改用你自己的会话。
  切勿在后续请求中重复发送 `wsa`。
- **你的应用自己的密钥**把风险爆炸半径隔离在单个应用 / 组织之内。**规划中：** RS256
  公钥分发（一应用一密钥）—— `verifyWsa` 已支持传入 `publicKey` 与 `algorithms: ['RS256']`。

## 开发

```bash
npm install
npm test          # node --test（无任何外部测试依赖）
npm run type-check # 跨各个包执行 tsc --noEmit
```

另请参阅 GPTBots 官方文档中权威的 GPTBots Workspace 扩展应用接入参考。
