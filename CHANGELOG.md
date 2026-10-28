# Changelog

## [0.2.0](https://github.com/vooon/go-masterfile/compare/v0.1.0...v0.2.0) (2026-10-28)


### ⚠ BREAKING CHANGES

* File, Open, Origin, ResolveOwners and the package-level Format/WritePlain are gone. Parse(data, apex) returns a *Zone with owners already resolved and the apex checked (ErrApexMismatch); New(apex) starts an empty one. Zone.Entries and Zone.Changed are exported fields; Format, WritePlain and Commit are methods. The editing operations are op values (Replace, Insert, Delete, DeleteOwner, AddRemove, Collapse) applied atomically with Zone.Apply; records travel as RR{Type, TTL, Content} data. Zone.Check is the opt-in gate for files served on their own (ErrNoOrigin, ErrNoSOA), so $INCLUDE fragments parse like any file.

### Features

* add the zone editing operations ([ec5bf01](https://github.com/vooon/go-masterfile/commit/ec5bf0178470558958b26e7172acff1b7bf9876e))
* add ToASCII and ToUnicode for internationalised names ([0ce815b](https://github.com/vooon/go-masterfile/commit/0ce815b62c2d13597b45e196345f0c30c9d759a2))
* add zone routing and reverse-zone helpers ([bb880d2](https://github.com/vooon/go-masterfile/commit/bb880d2fb5f149426de67e9b466d74934d810f20))
* implement the masterfile library ([b83620d](https://github.com/vooon/go-masterfile/commit/b83620df1668baf734b571715e71f8645fe2242d))
* initial masterfile library, CI and release automation ([efcdf3f](https://github.com/vooon/go-masterfile/commit/efcdf3ff53ac0db98ececdc29502ad402cb341a1))
* ToASCII and ToUnicode helpers for internationalised names ([1511f76](https://github.com/vooon/go-masterfile/commit/1511f7658549aff1608ba5155cfbe5c7c70bb272))
* unify parsing and editing in one Zone with patch-style operations ([80f8507](https://github.com/vooon/go-masterfile/commit/80f8507cf0fa83d6a7d112eecd427ac78efab878))
* zone routing and reverse-zone helpers ([4988eea](https://github.com/vooon/go-masterfile/commit/4988eea0189b114333a2872b5ab41471175a9888))

## 0.1.0 (2026-10-28)


### Features

* implement the masterfile library ([b83620d](https://github.com/vooon/go-masterfile/commit/b83620df1668baf734b571715e71f8645fe2242d))
* initial masterfile library, CI and release automation ([efcdf3f](https://github.com/vooon/go-masterfile/commit/efcdf3ff53ac0db98ececdc29502ad402cb341a1))
