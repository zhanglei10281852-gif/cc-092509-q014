# 专利与技术秘密档案管理服务

这是一个面向研发机构、法务部门和保密办公室的模块化后端，集中管理专利交底资料、技术秘密载体、移交批次、受控副本签发、查阅借阅、对外披露、归还、合规处置、载体盘点、版本与载体来源、密级库位、泄密事件、登录权限、审计以及可恢复后台任务。项目使用 FastAPI 与 SQLite，所有运行数据保存在单个本地数据库文件中，不依赖另行部署的数据库、缓存或消息队列。

## 已有能力

- 身份与权限：支持引导管理员、登录、会话、用户、角色和细粒度权限。
- 批次与二维码：移交批次保存项目、数量和稳定二维码载荷。
- 档案登记：登记专利交底、工艺文档、源代码介质等资产，保存密级库位和生命周期状态。
- 受控副本签发：一次事务内扣减来源载体、创建副本、记录损耗和版本来源事件。
- 查阅借阅归还：保存查阅用途、到期时间、部分归还和最终归还状态。
- 对外披露登记：使用幂等键登记合作方、披露范围和载体消耗，防止重复请求二次扣减。
- 位置脱敏：普通权限只能看到受限库位的替代码，授权人员可查看精确位置。
- 双人审批：合规处置、敏感库位解密等高风险操作要求申请人与审批人分离，并累计不同审批人的决定。
- 泄密事件追踪：事件可以关联档案或移交批次，保存严重度、调查状态和处置结果。
- 审计与任务：关键身份及业务操作留痕，后台任务支持去重、领取与完成。
- 离线移交包：分支机构定期导出加密移交包同步新增档案、审批结果和载体变更。每个包携带父包指针、负载摘要、链式包摘要和顺序号，可选 HMAC 签名；导入支持预演缺失依赖、分阶段提交和失败后断点续传；同一包重传返回原批次结果，不重复写入；同一档案两端分叉修改时保留双来源并进入人工裁决；导入完成后可独立核对摘要链、审计链、版本关系和当前有效状态。

## 离线移交包

分支与总部各自部署同一套服务，用 `ARCHIVE_SITE_ID` 标识站点（总部默认 `HQ`），可选 `ARCHIVE_PACKAGE_KEY` 配置包签名密钥（配置后导出包自动附带 HMAC 签名，导入时强制校验）。

- `POST /api/offline-packages/export`：以上一导出包为水位线，把新增档案、审批结果、载体变更打包。
- `POST /api/offline-packages/preview`：预演导入，不落库地报告缺失依赖（父包、前置批次/库位/档案、前置版本）与分叉。
- `POST /api/offline-packages/import`：登记并分阶段提交；逐条事务应用，失败后可再次调用继续；同一包重传返回原批次结果。
- `POST /api/offline-packages/{id}/commit`：继续提交已登记或失败的包。
- `GET /api/offline-packages/{id}/verify`：独立核对摘要链、顺序、审计链、版本关系和当前有效状态。
- `GET /api/offline-packages/forks`、`POST /api/offline-packages/forks/{id}/resolve`：查看分叉并人工裁决（保留本地或采用远端，两条来源都保留）。

无网络环境下也可以使用命令行完成导入与核对：

```bash
python -m app.cli import-package package.json
python -m app.cli verify-package BRANCH-A-PKG-000001
```

同步边界：离线包只承载新增档案、审批结果与载体变更（库位转移）；密级库位等主数据需在总部预先建立。分支对同步档案的其他写操作不进入离线包，如造成版本分叉会进入人工裁决。

## 运行环境

- Python 3.11
- SQLite 3，由 Python 标准库提供
- Linux、macOS 或 Windows

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

默认数据库位于 `./data/archives.db`，可用 `ARCHIVE_DATABASE_PATH` 指定其他路径。

## 初始化与完整性检查

```bash
python -m app.cli init-db
python -m app.cli check-db
```

## 启动 API

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 测试

```bash
python -m pytest
```

## 编译检查

```bash
python -m compileall -q app tests
```

## API 冒烟

```bash
python -m app.cli smoke
```
