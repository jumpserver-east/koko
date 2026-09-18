# 同步上游版本及开发分支

工作流位于 `.github/workflows/sync-version-branches.yml`，只在
`jumpserver-east/koko` 的默认分支 `docker-build` 上执行。源仓库为
`https://github.com/jumpserver/koko.git`，脚本只读取源仓库，并只向当前 fork 的
`origin` 推送。

## 同步规则

- 每周一北京时间 08:17 自动执行实际同步，也可手动运行；手动运行默认是 dry-run。
- `dev`、`v3`、`v4`、`v5` 精确镜像 upstream，必要时使用带 lease 的强制更新。
- `vX.Y.Z`、`vX.Y.Z-lts`、`vX.Y.Z-N-lts` 版本分支只创建或 fast-forward。
- 不删除 fork 独有分支，不同步 tag，不向 upstream 写入。
- 推送凭据优先使用 `SYNC_BRANCHES_TOKEN`，否则使用 `GITHUB_TOKEN`。

## 二开分支公约

- 上游标准分支（`dev`、`v3`、`v4`、`v5` 及 `vX.Y.Z*` 版本分支）只用于同步，
  不在组件仓库自动构建镜像。
- 客户二开分支使用 `客户名称@基于分支名称`，例如
  `ferror@v4.10.19-lts`。客户名称使用稳定、可读的字母、数字、`.`、`_` 或 `-`，
  `@` 后必须是实际存在的基线分支。
- 涉及多个组件时，lion、koko、lina、luna 和 docker-web 尽量使用相同的二开分支名；
  这样统一 Web 构建可以优先取同名分支。
- 不把 `docker-build` 作为应用源码分支，也不在二开分支中提交构建配置的临时改动。

## 构建逻辑

`build-component-image.yml` 只对非标准分支的 push 自动构建 koko EE 镜像。标准分支
以及 `docker-build`、`main`、`master` 的 push 被 workflow 入口和 job 条件双重过滤；
手动 `workflow_dispatch` 才能显式构建这些分支。构建使用触发 push 的 commit SHA，
避免构建期间分支头发生变化。

## 工作流与镜像构建策略

`docker-build` 只保留 `jumpserver-east` 自有的：

- `build-component-image.yml`
- `sync-version-branches.yml`

从 upstream 继承的 workflow 文件从 `docker-build` 删除。源码分支仍保持与 upstream
相同的提交，因此其中可能仍包含上游 workflow 文件；同步工作流通过 GitHub API 在
仓库级停用除上述白名单外、位于 `.github/workflows/` 的 YAML workflow。
GitHub 自动管理的 `Dependency Graph`（`dynamic/dependabot/update-graph`）等系统任务
不属于继承的 YAML 工作流，直接跳过；它们不支持普通 workflow 的停用 API。
停用或回读失败仍会让任务失败，日志会注明具体 workflow 路径及 ID。这个操作只作用于
`jumpserver-east/koko`，不会修改 `jumpserver/koko`。

同步创建 `dev`、所有 `v*` 开发/版本分支时不会自动构建 EE 镜像。自有构建工作流只在
push 其他分支或手动运行时构建；手动运行仍可显式选择标准分支。构建使用触发 push
的 commit SHA，避免构建期间分支头发生变化。

## Token 权限

Fine-grained PAT 的 Resource owner 选择 `jumpserver-east`，仓库选择 `koko`，授予
**Contents: Read and write** 与 **Workflows: Read and write**，保存为仓库 Actions
secret `SYNC_BRANCHES_TOKEN`。组织策略要求审批或 SSO 时还需完成对应授权。

## 本地验证

```bash
python3 .github/scripts/test_sync_version_branches.py
python3 .github/scripts/test_workflow_policy.py
DRY_RUN=true bash .github/scripts/sync-version-branches.sh
```
