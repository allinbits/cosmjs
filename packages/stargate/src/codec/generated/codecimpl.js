"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.tendermint = exports.ibc = exports.google = exports.cosmos = void 0;
var $protobuf = require("protobufjs/minimal");
const $Reader = $protobuf.Reader,
  $Writer = $protobuf.Writer,
  $util = $protobuf.util;
const $root = {};
exports.cosmos = $root.cosmos = (() => {
  const cosmos = {};
  cosmos.auth = (function () {
    const auth = {};
    auth.v1beta1 = (function () {
      const v1beta1 = {};
      v1beta1.BaseAccount = (function () {
        function BaseAccount(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        BaseAccount.prototype.address = "";
        BaseAccount.prototype.pubKey = null;
        BaseAccount.prototype.accountNumber = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
        BaseAccount.prototype.sequence = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
        BaseAccount.create = function create(properties) {
          return new BaseAccount(properties);
        };
        BaseAccount.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.address != null && Object.hasOwnProperty.call(m, "address")) w.uint32(10).string(m.address);
          if (m.pubKey != null && Object.hasOwnProperty.call(m, "pubKey"))
            $root.google.protobuf.Any.encode(m.pubKey, w.uint32(18).fork()).ldelim();
          if (m.accountNumber != null && Object.hasOwnProperty.call(m, "accountNumber"))
            w.uint32(24).uint64(m.accountNumber);
          if (m.sequence != null && Object.hasOwnProperty.call(m, "sequence"))
            w.uint32(32).uint64(m.sequence);
          return w;
        };
        BaseAccount.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.auth.v1beta1.BaseAccount();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.address = r.string();
                break;
              case 2:
                m.pubKey = $root.google.protobuf.Any.decode(r, r.uint32());
                break;
              case 3:
                m.accountNumber = r.uint64();
                break;
              case 4:
                m.sequence = r.uint64();
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return BaseAccount;
      })();
      v1beta1.ModuleAccount = (function () {
        function ModuleAccount(p) {
          this.permissions = [];
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        ModuleAccount.prototype.baseAccount = null;
        ModuleAccount.prototype.name = "";
        ModuleAccount.prototype.permissions = $util.emptyArray;
        ModuleAccount.create = function create(properties) {
          return new ModuleAccount(properties);
        };
        ModuleAccount.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.baseAccount != null && Object.hasOwnProperty.call(m, "baseAccount"))
            $root.cosmos.auth.v1beta1.BaseAccount.encode(m.baseAccount, w.uint32(10).fork()).ldelim();
          if (m.name != null && Object.hasOwnProperty.call(m, "name")) w.uint32(18).string(m.name);
          if (m.permissions != null && m.permissions.length) {
            for (var i = 0; i < m.permissions.length; ++i) w.uint32(26).string(m.permissions[i]);
          }
          return w;
        };
        ModuleAccount.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.auth.v1beta1.ModuleAccount();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.baseAccount = $root.cosmos.auth.v1beta1.BaseAccount.decode(r, r.uint32());
                break;
              case 2:
                m.name = r.string();
                break;
              case 3:
                if (!(m.permissions && m.permissions.length)) m.permissions = [];
                m.permissions.push(r.string());
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return ModuleAccount;
      })();
      v1beta1.Params = (function () {
        function Params(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        Params.prototype.maxMemoCharacters = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
        Params.prototype.txSigLimit = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
        Params.prototype.txSizeCostPerByte = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
        Params.prototype.sigVerifyCostEd25519 = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
        Params.prototype.sigVerifyCostSecp256k1 = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
        Params.create = function create(properties) {
          return new Params(properties);
        };
        Params.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.maxMemoCharacters != null && Object.hasOwnProperty.call(m, "maxMemoCharacters"))
            w.uint32(8).uint64(m.maxMemoCharacters);
          if (m.txSigLimit != null && Object.hasOwnProperty.call(m, "txSigLimit"))
            w.uint32(16).uint64(m.txSigLimit);
          if (m.txSizeCostPerByte != null && Object.hasOwnProperty.call(m, "txSizeCostPerByte"))
            w.uint32(24).uint64(m.txSizeCostPerByte);
          if (m.sigVerifyCostEd25519 != null && Object.hasOwnProperty.call(m, "sigVerifyCostEd25519"))
            w.uint32(32).uint64(m.sigVerifyCostEd25519);
          if (m.sigVerifyCostSecp256k1 != null && Object.hasOwnProperty.call(m, "sigVerifyCostSecp256k1"))
            w.uint32(40).uint64(m.sigVerifyCostSecp256k1);
          return w;
        };
        Params.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.auth.v1beta1.Params();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.maxMemoCharacters = r.uint64();
                break;
              case 2:
                m.txSigLimit = r.uint64();
                break;
              case 3:
                m.txSizeCostPerByte = r.uint64();
                break;
              case 4:
                m.sigVerifyCostEd25519 = r.uint64();
                break;
              case 5:
                m.sigVerifyCostSecp256k1 = r.uint64();
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return Params;
      })();
      v1beta1.Query = (function () {
        function Query(rpcImpl, requestDelimited, responseDelimited) {
          $protobuf.rpc.Service.call(this, rpcImpl, requestDelimited, responseDelimited);
        }
        (Query.prototype = Object.create($protobuf.rpc.Service.prototype)).constructor = Query;
        Query.create = function create(rpcImpl, requestDelimited, responseDelimited) {
          return new this(rpcImpl, requestDelimited, responseDelimited);
        };
        Object.defineProperty(
          (Query.prototype.account = function account(request, callback) {
            return this.rpcCall(
              account,
              $root.cosmos.auth.v1beta1.QueryAccountRequest,
              $root.cosmos.auth.v1beta1.QueryAccountResponse,
              request,
              callback,
            );
          }),
          "name",
          { value: "Account" },
        );
        Object.defineProperty(
          (Query.prototype.params = function params(request, callback) {
            return this.rpcCall(
              params,
              $root.cosmos.auth.v1beta1.QueryParamsRequest,
              $root.cosmos.auth.v1beta1.QueryParamsResponse,
              request,
              callback,
            );
          }),
          "name",
          { value: "Params" },
        );
        return Query;
      })();
      v1beta1.QueryAccountRequest = (function () {
        function QueryAccountRequest(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        QueryAccountRequest.prototype.address = "";
        QueryAccountRequest.create = function create(properties) {
          return new QueryAccountRequest(properties);
        };
        QueryAccountRequest.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.address != null && Object.hasOwnProperty.call(m, "address")) w.uint32(10).string(m.address);
          return w;
        };
        QueryAccountRequest.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.auth.v1beta1.QueryAccountRequest();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.address = r.string();
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return QueryAccountRequest;
      })();
      v1beta1.QueryAccountResponse = (function () {
        function QueryAccountResponse(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        QueryAccountResponse.prototype.account = null;
        QueryAccountResponse.create = function create(properties) {
          return new QueryAccountResponse(properties);
        };
        QueryAccountResponse.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.account != null && Object.hasOwnProperty.call(m, "account"))
            $root.google.protobuf.Any.encode(m.account, w.uint32(10).fork()).ldelim();
          return w;
        };
        QueryAccountResponse.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.auth.v1beta1.QueryAccountResponse();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.account = $root.google.protobuf.Any.decode(r, r.uint32());
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return QueryAccountResponse;
      })();
      v1beta1.QueryParamsRequest = (function () {
        function QueryParamsRequest(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        QueryParamsRequest.create = function create(properties) {
          return new QueryParamsRequest(properties);
        };
        QueryParamsRequest.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          return w;
        };
        QueryParamsRequest.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.auth.v1beta1.QueryParamsRequest();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return QueryParamsRequest;
      })();
      v1beta1.QueryParamsResponse = (function () {
        function QueryParamsResponse(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        QueryParamsResponse.prototype.params = null;
        QueryParamsResponse.create = function create(properties) {
          return new QueryParamsResponse(properties);
        };
        QueryParamsResponse.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.params != null && Object.hasOwnProperty.call(m, "params"))
            $root.cosmos.auth.v1beta1.Params.encode(m.params, w.uint32(10).fork()).ldelim();
          return w;
        };
        QueryParamsResponse.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.auth.v1beta1.QueryParamsResponse();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.params = $root.cosmos.auth.v1beta1.Params.decode(r, r.uint32());
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return QueryParamsResponse;
      })();
      return v1beta1;
    })();
    return auth;
  })();
  cosmos.bank = (function () {
    const bank = {};
    bank.v1beta1 = (function () {
      const v1beta1 = {};
      v1beta1.Query = (function () {
        function Query(rpcImpl, requestDelimited, responseDelimited) {
          $protobuf.rpc.Service.call(this, rpcImpl, requestDelimited, responseDelimited);
        }
        (Query.prototype = Object.create($protobuf.rpc.Service.prototype)).constructor = Query;
        Query.create = function create(rpcImpl, requestDelimited, responseDelimited) {
          return new this(rpcImpl, requestDelimited, responseDelimited);
        };
        Object.defineProperty(
          (Query.prototype.balance = function balance(request, callback) {
            return this.rpcCall(
              balance,
              $root.cosmos.bank.v1beta1.QueryBalanceRequest,
              $root.cosmos.bank.v1beta1.QueryBalanceResponse,
              request,
              callback,
            );
          }),
          "name",
          { value: "Balance" },
        );
        Object.defineProperty(
          (Query.prototype.allBalances = function allBalances(request, callback) {
            return this.rpcCall(
              allBalances,
              $root.cosmos.bank.v1beta1.QueryAllBalancesRequest,
              $root.cosmos.bank.v1beta1.QueryAllBalancesResponse,
              request,
              callback,
            );
          }),
          "name",
          { value: "AllBalances" },
        );
        Object.defineProperty(
          (Query.prototype.totalSupply = function totalSupply(request, callback) {
            return this.rpcCall(
              totalSupply,
              $root.cosmos.bank.v1beta1.QueryTotalSupplyRequest,
              $root.cosmos.bank.v1beta1.QueryTotalSupplyResponse,
              request,
              callback,
            );
          }),
          "name",
          { value: "TotalSupply" },
        );
        Object.defineProperty(
          (Query.prototype.supplyOf = function supplyOf(request, callback) {
            return this.rpcCall(
              supplyOf,
              $root.cosmos.bank.v1beta1.QuerySupplyOfRequest,
              $root.cosmos.bank.v1beta1.QuerySupplyOfResponse,
              request,
              callback,
            );
          }),
          "name",
          { value: "SupplyOf" },
        );
        Object.defineProperty(
          (Query.prototype.params = function params(request, callback) {
            return this.rpcCall(
              params,
              $root.cosmos.bank.v1beta1.QueryParamsRequest,
              $root.cosmos.bank.v1beta1.QueryParamsResponse,
              request,
              callback,
            );
          }),
          "name",
          { value: "Params" },
        );
        return Query;
      })();
      v1beta1.QueryBalanceRequest = (function () {
        function QueryBalanceRequest(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        QueryBalanceRequest.prototype.address = "";
        QueryBalanceRequest.prototype.denom = "";
        QueryBalanceRequest.create = function create(properties) {
          return new QueryBalanceRequest(properties);
        };
        QueryBalanceRequest.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.address != null && Object.hasOwnProperty.call(m, "address")) w.uint32(10).string(m.address);
          if (m.denom != null && Object.hasOwnProperty.call(m, "denom")) w.uint32(18).string(m.denom);
          return w;
        };
        QueryBalanceRequest.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.bank.v1beta1.QueryBalanceRequest();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.address = r.string();
                break;
              case 2:
                m.denom = r.string();
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return QueryBalanceRequest;
      })();
      v1beta1.QueryBalanceResponse = (function () {
        function QueryBalanceResponse(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        QueryBalanceResponse.prototype.balance = null;
        QueryBalanceResponse.create = function create(properties) {
          return new QueryBalanceResponse(properties);
        };
        QueryBalanceResponse.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.balance != null && Object.hasOwnProperty.call(m, "balance"))
            $root.cosmos.base.v1beta1.Coin.encode(m.balance, w.uint32(10).fork()).ldelim();
          return w;
        };
        QueryBalanceResponse.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.bank.v1beta1.QueryBalanceResponse();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.balance = $root.cosmos.base.v1beta1.Coin.decode(r, r.uint32());
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return QueryBalanceResponse;
      })();
      v1beta1.QueryAllBalancesRequest = (function () {
        function QueryAllBalancesRequest(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        QueryAllBalancesRequest.prototype.address = "";
        QueryAllBalancesRequest.prototype.pagination = null;
        QueryAllBalancesRequest.create = function create(properties) {
          return new QueryAllBalancesRequest(properties);
        };
        QueryAllBalancesRequest.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.address != null && Object.hasOwnProperty.call(m, "address")) w.uint32(10).string(m.address);
          if (m.pagination != null && Object.hasOwnProperty.call(m, "pagination"))
            $root.cosmos.base.query.v1beta1.PageRequest.encode(m.pagination, w.uint32(18).fork()).ldelim();
          return w;
        };
        QueryAllBalancesRequest.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.bank.v1beta1.QueryAllBalancesRequest();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.address = r.string();
                break;
              case 2:
                m.pagination = $root.cosmos.base.query.v1beta1.PageRequest.decode(r, r.uint32());
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return QueryAllBalancesRequest;
      })();
      v1beta1.QueryAllBalancesResponse = (function () {
        function QueryAllBalancesResponse(p) {
          this.balances = [];
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        QueryAllBalancesResponse.prototype.balances = $util.emptyArray;
        QueryAllBalancesResponse.prototype.pagination = null;
        QueryAllBalancesResponse.create = function create(properties) {
          return new QueryAllBalancesResponse(properties);
        };
        QueryAllBalancesResponse.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.balances != null && m.balances.length) {
            for (var i = 0; i < m.balances.length; ++i)
              $root.cosmos.base.v1beta1.Coin.encode(m.balances[i], w.uint32(10).fork()).ldelim();
          }
          if (m.pagination != null && Object.hasOwnProperty.call(m, "pagination"))
            $root.cosmos.base.query.v1beta1.PageResponse.encode(m.pagination, w.uint32(18).fork()).ldelim();
          return w;
        };
        QueryAllBalancesResponse.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.bank.v1beta1.QueryAllBalancesResponse();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                if (!(m.balances && m.balances.length)) m.balances = [];
                m.balances.push($root.cosmos.base.v1beta1.Coin.decode(r, r.uint32()));
                break;
              case 2:
                m.pagination = $root.cosmos.base.query.v1beta1.PageResponse.decode(r, r.uint32());
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return QueryAllBalancesResponse;
      })();
      v1beta1.QueryTotalSupplyRequest = (function () {
        function QueryTotalSupplyRequest(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        QueryTotalSupplyRequest.create = function create(properties) {
          return new QueryTotalSupplyRequest(properties);
        };
        QueryTotalSupplyRequest.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          return w;
        };
        QueryTotalSupplyRequest.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.bank.v1beta1.QueryTotalSupplyRequest();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return QueryTotalSupplyRequest;
      })();
      v1beta1.QueryTotalSupplyResponse = (function () {
        function QueryTotalSupplyResponse(p) {
          this.supply = [];
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        QueryTotalSupplyResponse.prototype.supply = $util.emptyArray;
        QueryTotalSupplyResponse.create = function create(properties) {
          return new QueryTotalSupplyResponse(properties);
        };
        QueryTotalSupplyResponse.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.supply != null && m.supply.length) {
            for (var i = 0; i < m.supply.length; ++i)
              $root.cosmos.base.v1beta1.Coin.encode(m.supply[i], w.uint32(10).fork()).ldelim();
          }
          return w;
        };
        QueryTotalSupplyResponse.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.bank.v1beta1.QueryTotalSupplyResponse();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                if (!(m.supply && m.supply.length)) m.supply = [];
                m.supply.push($root.cosmos.base.v1beta1.Coin.decode(r, r.uint32()));
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return QueryTotalSupplyResponse;
      })();
      v1beta1.QuerySupplyOfRequest = (function () {
        function QuerySupplyOfRequest(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        QuerySupplyOfRequest.prototype.denom = "";
        QuerySupplyOfRequest.create = function create(properties) {
          return new QuerySupplyOfRequest(properties);
        };
        QuerySupplyOfRequest.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.denom != null && Object.hasOwnProperty.call(m, "denom")) w.uint32(10).string(m.denom);
          return w;
        };
        QuerySupplyOfRequest.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.bank.v1beta1.QuerySupplyOfRequest();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.denom = r.string();
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return QuerySupplyOfRequest;
      })();
      v1beta1.QuerySupplyOfResponse = (function () {
        function QuerySupplyOfResponse(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        QuerySupplyOfResponse.prototype.amount = null;
        QuerySupplyOfResponse.create = function create(properties) {
          return new QuerySupplyOfResponse(properties);
        };
        QuerySupplyOfResponse.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.amount != null && Object.hasOwnProperty.call(m, "amount"))
            $root.cosmos.base.v1beta1.Coin.encode(m.amount, w.uint32(10).fork()).ldelim();
          return w;
        };
        QuerySupplyOfResponse.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.bank.v1beta1.QuerySupplyOfResponse();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.amount = $root.cosmos.base.v1beta1.Coin.decode(r, r.uint32());
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return QuerySupplyOfResponse;
      })();
      v1beta1.QueryParamsRequest = (function () {
        function QueryParamsRequest(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        QueryParamsRequest.create = function create(properties) {
          return new QueryParamsRequest(properties);
        };
        QueryParamsRequest.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          return w;
        };
        QueryParamsRequest.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.bank.v1beta1.QueryParamsRequest();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return QueryParamsRequest;
      })();
      v1beta1.QueryParamsResponse = (function () {
        function QueryParamsResponse(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        QueryParamsResponse.prototype.params = null;
        QueryParamsResponse.create = function create(properties) {
          return new QueryParamsResponse(properties);
        };
        QueryParamsResponse.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.params != null && Object.hasOwnProperty.call(m, "params"))
            $root.cosmos.auth.v1beta1.Params.encode(m.params, w.uint32(10).fork()).ldelim();
          return w;
        };
        QueryParamsResponse.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.bank.v1beta1.QueryParamsResponse();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.params = $root.cosmos.auth.v1beta1.Params.decode(r, r.uint32());
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return QueryParamsResponse;
      })();
      return v1beta1;
    })();
    return bank;
  })();
  cosmos.base = (function () {
    const base = {};
    base.query = (function () {
      const query = {};
      query.v1beta1 = (function () {
        const v1beta1 = {};
        v1beta1.PageRequest = (function () {
          function PageRequest(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          PageRequest.prototype.key = $util.newBuffer([]);
          PageRequest.prototype.offset = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
          PageRequest.prototype.limit = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
          PageRequest.prototype.countTotal = false;
          PageRequest.create = function create(properties) {
            return new PageRequest(properties);
          };
          PageRequest.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.key != null && Object.hasOwnProperty.call(m, "key")) w.uint32(10).bytes(m.key);
            if (m.offset != null && Object.hasOwnProperty.call(m, "offset")) w.uint32(16).uint64(m.offset);
            if (m.limit != null && Object.hasOwnProperty.call(m, "limit")) w.uint32(24).uint64(m.limit);
            if (m.countTotal != null && Object.hasOwnProperty.call(m, "countTotal"))
              w.uint32(32).bool(m.countTotal);
            return w;
          };
          PageRequest.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.cosmos.base.query.v1beta1.PageRequest();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.key = r.bytes();
                  break;
                case 2:
                  m.offset = r.uint64();
                  break;
                case 3:
                  m.limit = r.uint64();
                  break;
                case 4:
                  m.countTotal = r.bool();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return PageRequest;
        })();
        v1beta1.PageResponse = (function () {
          function PageResponse(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          PageResponse.prototype.nextKey = $util.newBuffer([]);
          PageResponse.prototype.total = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
          PageResponse.create = function create(properties) {
            return new PageResponse(properties);
          };
          PageResponse.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.nextKey != null && Object.hasOwnProperty.call(m, "nextKey")) w.uint32(10).bytes(m.nextKey);
            if (m.total != null && Object.hasOwnProperty.call(m, "total")) w.uint32(16).uint64(m.total);
            return w;
          };
          PageResponse.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.cosmos.base.query.v1beta1.PageResponse();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.nextKey = r.bytes();
                  break;
                case 2:
                  m.total = r.uint64();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return PageResponse;
        })();
        return v1beta1;
      })();
      return query;
    })();
    base.v1beta1 = (function () {
      const v1beta1 = {};
      v1beta1.Coin = (function () {
        function Coin(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        Coin.prototype.denom = "";
        Coin.prototype.amount = "";
        Coin.create = function create(properties) {
          return new Coin(properties);
        };
        Coin.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.denom != null && Object.hasOwnProperty.call(m, "denom")) w.uint32(10).string(m.denom);
          if (m.amount != null && Object.hasOwnProperty.call(m, "amount")) w.uint32(18).string(m.amount);
          return w;
        };
        Coin.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.base.v1beta1.Coin();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.denom = r.string();
                break;
              case 2:
                m.amount = r.string();
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return Coin;
      })();
      v1beta1.DecCoin = (function () {
        function DecCoin(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        DecCoin.prototype.denom = "";
        DecCoin.prototype.amount = "";
        DecCoin.create = function create(properties) {
          return new DecCoin(properties);
        };
        DecCoin.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.denom != null && Object.hasOwnProperty.call(m, "denom")) w.uint32(10).string(m.denom);
          if (m.amount != null && Object.hasOwnProperty.call(m, "amount")) w.uint32(18).string(m.amount);
          return w;
        };
        DecCoin.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.base.v1beta1.DecCoin();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.denom = r.string();
                break;
              case 2:
                m.amount = r.string();
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return DecCoin;
      })();
      v1beta1.IntProto = (function () {
        function IntProto(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        IntProto.prototype.int = "";
        IntProto.create = function create(properties) {
          return new IntProto(properties);
        };
        IntProto.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.int != null && Object.hasOwnProperty.call(m, "int")) w.uint32(10).string(m.int);
          return w;
        };
        IntProto.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.base.v1beta1.IntProto();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.int = r.string();
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return IntProto;
      })();
      v1beta1.DecProto = (function () {
        function DecProto(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        DecProto.prototype.dec = "";
        DecProto.create = function create(properties) {
          return new DecProto(properties);
        };
        DecProto.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.dec != null && Object.hasOwnProperty.call(m, "dec")) w.uint32(10).string(m.dec);
          return w;
        };
        DecProto.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.base.v1beta1.DecProto();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.dec = r.string();
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return DecProto;
      })();
      return v1beta1;
    })();
    return base;
  })();
  cosmos.crypto = (function () {
    const crypto = {};
    crypto.multisig = (function () {
      const multisig = {};
      multisig.v1beta1 = (function () {
        const v1beta1 = {};
        v1beta1.MultiSignature = (function () {
          function MultiSignature(p) {
            this.signatures = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MultiSignature.prototype.signatures = $util.emptyArray;
          MultiSignature.create = function create(properties) {
            return new MultiSignature(properties);
          };
          MultiSignature.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.signatures != null && m.signatures.length) {
              for (var i = 0; i < m.signatures.length; ++i) w.uint32(10).bytes(m.signatures[i]);
            }
            return w;
          };
          MultiSignature.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.cosmos.crypto.multisig.v1beta1.MultiSignature();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  if (!(m.signatures && m.signatures.length)) m.signatures = [];
                  m.signatures.push(r.bytes());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MultiSignature;
        })();
        v1beta1.CompactBitArray = (function () {
          function CompactBitArray(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          CompactBitArray.prototype.extraBitsStored = 0;
          CompactBitArray.prototype.elems = $util.newBuffer([]);
          CompactBitArray.create = function create(properties) {
            return new CompactBitArray(properties);
          };
          CompactBitArray.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.extraBitsStored != null && Object.hasOwnProperty.call(m, "extraBitsStored"))
              w.uint32(8).uint32(m.extraBitsStored);
            if (m.elems != null && Object.hasOwnProperty.call(m, "elems")) w.uint32(18).bytes(m.elems);
            return w;
          };
          CompactBitArray.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.cosmos.crypto.multisig.v1beta1.CompactBitArray();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.extraBitsStored = r.uint32();
                  break;
                case 2:
                  m.elems = r.bytes();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return CompactBitArray;
        })();
        return v1beta1;
      })();
      return multisig;
    })();
    crypto.secp256k1 = (function () {
      const secp256k1 = {};
      secp256k1.PubKey = (function () {
        function PubKey(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        PubKey.prototype.key = $util.newBuffer([]);
        PubKey.create = function create(properties) {
          return new PubKey(properties);
        };
        PubKey.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.key != null && Object.hasOwnProperty.call(m, "key")) w.uint32(10).bytes(m.key);
          return w;
        };
        PubKey.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.crypto.secp256k1.PubKey();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.key = r.bytes();
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return PubKey;
      })();
      secp256k1.PrivKey = (function () {
        function PrivKey(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        PrivKey.prototype.key = $util.newBuffer([]);
        PrivKey.create = function create(properties) {
          return new PrivKey(properties);
        };
        PrivKey.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.key != null && Object.hasOwnProperty.call(m, "key")) w.uint32(10).bytes(m.key);
          return w;
        };
        PrivKey.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.crypto.secp256k1.PrivKey();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.key = r.bytes();
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return PrivKey;
      })();
      return secp256k1;
    })();
    return crypto;
  })();
  cosmos.tx = (function () {
    const tx = {};
    tx.signing = (function () {
      const signing = {};
      signing.v1beta1 = (function () {
        const v1beta1 = {};
        v1beta1.SignMode = (function () {
          const valuesById = {},
            values = Object.create(valuesById);
          values[(valuesById[0] = "SIGN_MODE_UNSPECIFIED")] = 0;
          values[(valuesById[1] = "SIGN_MODE_DIRECT")] = 1;
          values[(valuesById[2] = "SIGN_MODE_TEXTUAL")] = 2;
          values[(valuesById[127] = "SIGN_MODE_LEGACY_AMINO_JSON")] = 127;
          return values;
        })();
        v1beta1.SignatureDescriptors = (function () {
          function SignatureDescriptors(p) {
            this.signatures = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          SignatureDescriptors.prototype.signatures = $util.emptyArray;
          SignatureDescriptors.create = function create(properties) {
            return new SignatureDescriptors(properties);
          };
          SignatureDescriptors.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.signatures != null && m.signatures.length) {
              for (var i = 0; i < m.signatures.length; ++i)
                $root.cosmos.tx.signing.v1beta1.SignatureDescriptor.encode(
                  m.signatures[i],
                  w.uint32(10).fork(),
                ).ldelim();
            }
            return w;
          };
          SignatureDescriptors.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.cosmos.tx.signing.v1beta1.SignatureDescriptors();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  if (!(m.signatures && m.signatures.length)) m.signatures = [];
                  m.signatures.push(
                    $root.cosmos.tx.signing.v1beta1.SignatureDescriptor.decode(r, r.uint32()),
                  );
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return SignatureDescriptors;
        })();
        v1beta1.SignatureDescriptor = (function () {
          function SignatureDescriptor(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          SignatureDescriptor.prototype.publicKey = null;
          SignatureDescriptor.prototype.data = null;
          SignatureDescriptor.prototype.sequence = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
          SignatureDescriptor.create = function create(properties) {
            return new SignatureDescriptor(properties);
          };
          SignatureDescriptor.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.publicKey != null && Object.hasOwnProperty.call(m, "publicKey"))
              $root.google.protobuf.Any.encode(m.publicKey, w.uint32(10).fork()).ldelim();
            if (m.data != null && Object.hasOwnProperty.call(m, "data"))
              $root.cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.encode(
                m.data,
                w.uint32(18).fork(),
              ).ldelim();
            if (m.sequence != null && Object.hasOwnProperty.call(m, "sequence"))
              w.uint32(24).uint64(m.sequence);
            return w;
          };
          SignatureDescriptor.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.cosmos.tx.signing.v1beta1.SignatureDescriptor();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.publicKey = $root.google.protobuf.Any.decode(r, r.uint32());
                  break;
                case 2:
                  m.data = $root.cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.decode(r, r.uint32());
                  break;
                case 3:
                  m.sequence = r.uint64();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          SignatureDescriptor.Data = (function () {
            function Data(p) {
              if (p)
                for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                  if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
            }
            Data.prototype.single = null;
            Data.prototype.multi = null;
            let $oneOfFields;
            Object.defineProperty(Data.prototype, "sum", {
              get: $util.oneOfGetter(($oneOfFields = ["single", "multi"])),
              set: $util.oneOfSetter($oneOfFields),
            });
            Data.create = function create(properties) {
              return new Data(properties);
            };
            Data.encode = function encode(m, w) {
              if (!w) w = $Writer.create();
              if (m.single != null && Object.hasOwnProperty.call(m, "single"))
                $root.cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.Single.encode(
                  m.single,
                  w.uint32(10).fork(),
                ).ldelim();
              if (m.multi != null && Object.hasOwnProperty.call(m, "multi"))
                $root.cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.Multi.encode(
                  m.multi,
                  w.uint32(18).fork(),
                ).ldelim();
              return w;
            };
            Data.decode = function decode(r, l) {
              if (!(r instanceof $Reader)) r = $Reader.create(r);
              var c = l === undefined ? r.len : r.pos + l,
                m = new $root.cosmos.tx.signing.v1beta1.SignatureDescriptor.Data();
              while (r.pos < c) {
                var t = r.uint32();
                switch (t >>> 3) {
                  case 1:
                    m.single = $root.cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.Single.decode(
                      r,
                      r.uint32(),
                    );
                    break;
                  case 2:
                    m.multi = $root.cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.Multi.decode(
                      r,
                      r.uint32(),
                    );
                    break;
                  default:
                    r.skipType(t & 7);
                    break;
                }
              }
              return m;
            };
            Data.Single = (function () {
              function Single(p) {
                if (p)
                  for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                    if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
              }
              Single.prototype.mode = 0;
              Single.prototype.signature = $util.newBuffer([]);
              Single.create = function create(properties) {
                return new Single(properties);
              };
              Single.encode = function encode(m, w) {
                if (!w) w = $Writer.create();
                if (m.mode != null && Object.hasOwnProperty.call(m, "mode")) w.uint32(8).int32(m.mode);
                if (m.signature != null && Object.hasOwnProperty.call(m, "signature"))
                  w.uint32(18).bytes(m.signature);
                return w;
              };
              Single.decode = function decode(r, l) {
                if (!(r instanceof $Reader)) r = $Reader.create(r);
                var c = l === undefined ? r.len : r.pos + l,
                  m = new $root.cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.Single();
                while (r.pos < c) {
                  var t = r.uint32();
                  switch (t >>> 3) {
                    case 1:
                      m.mode = r.int32();
                      break;
                    case 2:
                      m.signature = r.bytes();
                      break;
                    default:
                      r.skipType(t & 7);
                      break;
                  }
                }
                return m;
              };
              return Single;
            })();
            Data.Multi = (function () {
              function Multi(p) {
                this.signatures = [];
                if (p)
                  for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                    if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
              }
              Multi.prototype.bitarray = null;
              Multi.prototype.signatures = $util.emptyArray;
              Multi.create = function create(properties) {
                return new Multi(properties);
              };
              Multi.encode = function encode(m, w) {
                if (!w) w = $Writer.create();
                if (m.bitarray != null && Object.hasOwnProperty.call(m, "bitarray"))
                  $root.cosmos.crypto.multisig.v1beta1.CompactBitArray.encode(
                    m.bitarray,
                    w.uint32(10).fork(),
                  ).ldelim();
                if (m.signatures != null && m.signatures.length) {
                  for (var i = 0; i < m.signatures.length; ++i)
                    $root.cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.encode(
                      m.signatures[i],
                      w.uint32(18).fork(),
                    ).ldelim();
                }
                return w;
              };
              Multi.decode = function decode(r, l) {
                if (!(r instanceof $Reader)) r = $Reader.create(r);
                var c = l === undefined ? r.len : r.pos + l,
                  m = new $root.cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.Multi();
                while (r.pos < c) {
                  var t = r.uint32();
                  switch (t >>> 3) {
                    case 1:
                      m.bitarray = $root.cosmos.crypto.multisig.v1beta1.CompactBitArray.decode(r, r.uint32());
                      break;
                    case 2:
                      if (!(m.signatures && m.signatures.length)) m.signatures = [];
                      m.signatures.push(
                        $root.cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.decode(r, r.uint32()),
                      );
                      break;
                    default:
                      r.skipType(t & 7);
                      break;
                  }
                }
                return m;
              };
              return Multi;
            })();
            return Data;
          })();
          return SignatureDescriptor;
        })();
        return v1beta1;
      })();
      return signing;
    })();
    tx.v1beta1 = (function () {
      const v1beta1 = {};
      v1beta1.Tx = (function () {
        function Tx(p) {
          this.signatures = [];
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        Tx.prototype.body = null;
        Tx.prototype.authInfo = null;
        Tx.prototype.signatures = $util.emptyArray;
        Tx.create = function create(properties) {
          return new Tx(properties);
        };
        Tx.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.body != null && Object.hasOwnProperty.call(m, "body"))
            $root.cosmos.tx.v1beta1.TxBody.encode(m.body, w.uint32(10).fork()).ldelim();
          if (m.authInfo != null && Object.hasOwnProperty.call(m, "authInfo"))
            $root.cosmos.tx.v1beta1.AuthInfo.encode(m.authInfo, w.uint32(18).fork()).ldelim();
          if (m.signatures != null && m.signatures.length) {
            for (var i = 0; i < m.signatures.length; ++i) w.uint32(26).bytes(m.signatures[i]);
          }
          return w;
        };
        Tx.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.tx.v1beta1.Tx();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.body = $root.cosmos.tx.v1beta1.TxBody.decode(r, r.uint32());
                break;
              case 2:
                m.authInfo = $root.cosmos.tx.v1beta1.AuthInfo.decode(r, r.uint32());
                break;
              case 3:
                if (!(m.signatures && m.signatures.length)) m.signatures = [];
                m.signatures.push(r.bytes());
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return Tx;
      })();
      v1beta1.TxRaw = (function () {
        function TxRaw(p) {
          this.signatures = [];
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        TxRaw.prototype.bodyBytes = $util.newBuffer([]);
        TxRaw.prototype.authInfoBytes = $util.newBuffer([]);
        TxRaw.prototype.signatures = $util.emptyArray;
        TxRaw.create = function create(properties) {
          return new TxRaw(properties);
        };
        TxRaw.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.bodyBytes != null && Object.hasOwnProperty.call(m, "bodyBytes"))
            w.uint32(10).bytes(m.bodyBytes);
          if (m.authInfoBytes != null && Object.hasOwnProperty.call(m, "authInfoBytes"))
            w.uint32(18).bytes(m.authInfoBytes);
          if (m.signatures != null && m.signatures.length) {
            for (var i = 0; i < m.signatures.length; ++i) w.uint32(26).bytes(m.signatures[i]);
          }
          return w;
        };
        TxRaw.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.tx.v1beta1.TxRaw();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.bodyBytes = r.bytes();
                break;
              case 2:
                m.authInfoBytes = r.bytes();
                break;
              case 3:
                if (!(m.signatures && m.signatures.length)) m.signatures = [];
                m.signatures.push(r.bytes());
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return TxRaw;
      })();
      v1beta1.SignDoc = (function () {
        function SignDoc(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        SignDoc.prototype.bodyBytes = $util.newBuffer([]);
        SignDoc.prototype.authInfoBytes = $util.newBuffer([]);
        SignDoc.prototype.chainId = "";
        SignDoc.prototype.accountNumber = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
        SignDoc.create = function create(properties) {
          return new SignDoc(properties);
        };
        SignDoc.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.bodyBytes != null && Object.hasOwnProperty.call(m, "bodyBytes"))
            w.uint32(10).bytes(m.bodyBytes);
          if (m.authInfoBytes != null && Object.hasOwnProperty.call(m, "authInfoBytes"))
            w.uint32(18).bytes(m.authInfoBytes);
          if (m.chainId != null && Object.hasOwnProperty.call(m, "chainId")) w.uint32(26).string(m.chainId);
          if (m.accountNumber != null && Object.hasOwnProperty.call(m, "accountNumber"))
            w.uint32(32).uint64(m.accountNumber);
          return w;
        };
        SignDoc.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.tx.v1beta1.SignDoc();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.bodyBytes = r.bytes();
                break;
              case 2:
                m.authInfoBytes = r.bytes();
                break;
              case 3:
                m.chainId = r.string();
                break;
              case 4:
                m.accountNumber = r.uint64();
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return SignDoc;
      })();
      v1beta1.TxBody = (function () {
        function TxBody(p) {
          this.messages = [];
          this.extensionOptions = [];
          this.nonCriticalExtensionOptions = [];
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        TxBody.prototype.messages = $util.emptyArray;
        TxBody.prototype.memo = "";
        TxBody.prototype.timeoutHeight = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
        TxBody.prototype.extensionOptions = $util.emptyArray;
        TxBody.prototype.nonCriticalExtensionOptions = $util.emptyArray;
        TxBody.create = function create(properties) {
          return new TxBody(properties);
        };
        TxBody.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.messages != null && m.messages.length) {
            for (var i = 0; i < m.messages.length; ++i)
              $root.google.protobuf.Any.encode(m.messages[i], w.uint32(10).fork()).ldelim();
          }
          if (m.memo != null && Object.hasOwnProperty.call(m, "memo")) w.uint32(18).string(m.memo);
          if (m.timeoutHeight != null && Object.hasOwnProperty.call(m, "timeoutHeight"))
            w.uint32(24).uint64(m.timeoutHeight);
          if (m.extensionOptions != null && m.extensionOptions.length) {
            for (var i = 0; i < m.extensionOptions.length; ++i)
              $root.google.protobuf.Any.encode(m.extensionOptions[i], w.uint32(8186).fork()).ldelim();
          }
          if (m.nonCriticalExtensionOptions != null && m.nonCriticalExtensionOptions.length) {
            for (var i = 0; i < m.nonCriticalExtensionOptions.length; ++i)
              $root.google.protobuf.Any.encode(
                m.nonCriticalExtensionOptions[i],
                w.uint32(16378).fork(),
              ).ldelim();
          }
          return w;
        };
        TxBody.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.tx.v1beta1.TxBody();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                if (!(m.messages && m.messages.length)) m.messages = [];
                m.messages.push($root.google.protobuf.Any.decode(r, r.uint32()));
                break;
              case 2:
                m.memo = r.string();
                break;
              case 3:
                m.timeoutHeight = r.uint64();
                break;
              case 1023:
                if (!(m.extensionOptions && m.extensionOptions.length)) m.extensionOptions = [];
                m.extensionOptions.push($root.google.protobuf.Any.decode(r, r.uint32()));
                break;
              case 2047:
                if (!(m.nonCriticalExtensionOptions && m.nonCriticalExtensionOptions.length))
                  m.nonCriticalExtensionOptions = [];
                m.nonCriticalExtensionOptions.push($root.google.protobuf.Any.decode(r, r.uint32()));
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return TxBody;
      })();
      v1beta1.AuthInfo = (function () {
        function AuthInfo(p) {
          this.signerInfos = [];
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        AuthInfo.prototype.signerInfos = $util.emptyArray;
        AuthInfo.prototype.fee = null;
        AuthInfo.create = function create(properties) {
          return new AuthInfo(properties);
        };
        AuthInfo.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.signerInfos != null && m.signerInfos.length) {
            for (var i = 0; i < m.signerInfos.length; ++i)
              $root.cosmos.tx.v1beta1.SignerInfo.encode(m.signerInfos[i], w.uint32(10).fork()).ldelim();
          }
          if (m.fee != null && Object.hasOwnProperty.call(m, "fee"))
            $root.cosmos.tx.v1beta1.Fee.encode(m.fee, w.uint32(18).fork()).ldelim();
          return w;
        };
        AuthInfo.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.tx.v1beta1.AuthInfo();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                if (!(m.signerInfos && m.signerInfos.length)) m.signerInfos = [];
                m.signerInfos.push($root.cosmos.tx.v1beta1.SignerInfo.decode(r, r.uint32()));
                break;
              case 2:
                m.fee = $root.cosmos.tx.v1beta1.Fee.decode(r, r.uint32());
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return AuthInfo;
      })();
      v1beta1.SignerInfo = (function () {
        function SignerInfo(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        SignerInfo.prototype.publicKey = null;
        SignerInfo.prototype.modeInfo = null;
        SignerInfo.prototype.sequence = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
        SignerInfo.create = function create(properties) {
          return new SignerInfo(properties);
        };
        SignerInfo.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.publicKey != null && Object.hasOwnProperty.call(m, "publicKey"))
            $root.google.protobuf.Any.encode(m.publicKey, w.uint32(10).fork()).ldelim();
          if (m.modeInfo != null && Object.hasOwnProperty.call(m, "modeInfo"))
            $root.cosmos.tx.v1beta1.ModeInfo.encode(m.modeInfo, w.uint32(18).fork()).ldelim();
          if (m.sequence != null && Object.hasOwnProperty.call(m, "sequence"))
            w.uint32(24).uint64(m.sequence);
          return w;
        };
        SignerInfo.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.tx.v1beta1.SignerInfo();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.publicKey = $root.google.protobuf.Any.decode(r, r.uint32());
                break;
              case 2:
                m.modeInfo = $root.cosmos.tx.v1beta1.ModeInfo.decode(r, r.uint32());
                break;
              case 3:
                m.sequence = r.uint64();
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return SignerInfo;
      })();
      v1beta1.ModeInfo = (function () {
        function ModeInfo(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        ModeInfo.prototype.single = null;
        ModeInfo.prototype.multi = null;
        let $oneOfFields;
        Object.defineProperty(ModeInfo.prototype, "sum", {
          get: $util.oneOfGetter(($oneOfFields = ["single", "multi"])),
          set: $util.oneOfSetter($oneOfFields),
        });
        ModeInfo.create = function create(properties) {
          return new ModeInfo(properties);
        };
        ModeInfo.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.single != null && Object.hasOwnProperty.call(m, "single"))
            $root.cosmos.tx.v1beta1.ModeInfo.Single.encode(m.single, w.uint32(10).fork()).ldelim();
          if (m.multi != null && Object.hasOwnProperty.call(m, "multi"))
            $root.cosmos.tx.v1beta1.ModeInfo.Multi.encode(m.multi, w.uint32(18).fork()).ldelim();
          return w;
        };
        ModeInfo.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.tx.v1beta1.ModeInfo();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.single = $root.cosmos.tx.v1beta1.ModeInfo.Single.decode(r, r.uint32());
                break;
              case 2:
                m.multi = $root.cosmos.tx.v1beta1.ModeInfo.Multi.decode(r, r.uint32());
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        ModeInfo.Single = (function () {
          function Single(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          Single.prototype.mode = 0;
          Single.create = function create(properties) {
            return new Single(properties);
          };
          Single.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.mode != null && Object.hasOwnProperty.call(m, "mode")) w.uint32(8).int32(m.mode);
            return w;
          };
          Single.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.cosmos.tx.v1beta1.ModeInfo.Single();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.mode = r.int32();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return Single;
        })();
        ModeInfo.Multi = (function () {
          function Multi(p) {
            this.modeInfos = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          Multi.prototype.bitarray = null;
          Multi.prototype.modeInfos = $util.emptyArray;
          Multi.create = function create(properties) {
            return new Multi(properties);
          };
          Multi.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.bitarray != null && Object.hasOwnProperty.call(m, "bitarray"))
              $root.cosmos.crypto.multisig.v1beta1.CompactBitArray.encode(
                m.bitarray,
                w.uint32(10).fork(),
              ).ldelim();
            if (m.modeInfos != null && m.modeInfos.length) {
              for (var i = 0; i < m.modeInfos.length; ++i)
                $root.cosmos.tx.v1beta1.ModeInfo.encode(m.modeInfos[i], w.uint32(18).fork()).ldelim();
            }
            return w;
          };
          Multi.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.cosmos.tx.v1beta1.ModeInfo.Multi();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.bitarray = $root.cosmos.crypto.multisig.v1beta1.CompactBitArray.decode(r, r.uint32());
                  break;
                case 2:
                  if (!(m.modeInfos && m.modeInfos.length)) m.modeInfos = [];
                  m.modeInfos.push($root.cosmos.tx.v1beta1.ModeInfo.decode(r, r.uint32()));
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return Multi;
        })();
        return ModeInfo;
      })();
      v1beta1.Fee = (function () {
        function Fee(p) {
          this.amount = [];
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        Fee.prototype.amount = $util.emptyArray;
        Fee.prototype.gasLimit = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
        Fee.prototype.payer = "";
        Fee.create = function create(properties) {
          return new Fee(properties);
        };
        Fee.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.amount != null && m.amount.length) {
            for (var i = 0; i < m.amount.length; ++i)
              $root.cosmos.base.v1beta1.Coin.encode(m.amount[i], w.uint32(10).fork()).ldelim();
          }
          if (m.gasLimit != null && Object.hasOwnProperty.call(m, "gasLimit"))
            w.uint32(16).uint64(m.gasLimit);
          if (m.payer != null && Object.hasOwnProperty.call(m, "payer")) w.uint32(26).string(m.payer);
          return w;
        };
        Fee.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.cosmos.tx.v1beta1.Fee();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                if (!(m.amount && m.amount.length)) m.amount = [];
                m.amount.push($root.cosmos.base.v1beta1.Coin.decode(r, r.uint32()));
                break;
              case 2:
                m.gasLimit = r.uint64();
                break;
              case 3:
                m.payer = r.string();
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return Fee;
      })();
      return v1beta1;
    })();
    return tx;
  })();
  return cosmos;
})();
exports.google = $root.google = (() => {
  const google = {};
  google.protobuf = (function () {
    const protobuf = {};
    protobuf.Any = (function () {
      function Any(p) {
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      Any.prototype.type_url = "";
      Any.prototype.value = $util.newBuffer([]);
      Any.create = function create(properties) {
        return new Any(properties);
      };
      Any.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.type_url != null && Object.hasOwnProperty.call(m, "type_url")) w.uint32(10).string(m.type_url);
        if (m.value != null && Object.hasOwnProperty.call(m, "value")) w.uint32(18).bytes(m.value);
        return w;
      };
      Any.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.Any();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              m.type_url = r.string();
              break;
            case 2:
              m.value = r.bytes();
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return Any;
    })();
    protobuf.FileDescriptorSet = (function () {
      function FileDescriptorSet(p) {
        this.file = [];
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      FileDescriptorSet.prototype.file = $util.emptyArray;
      FileDescriptorSet.create = function create(properties) {
        return new FileDescriptorSet(properties);
      };
      FileDescriptorSet.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.file != null && m.file.length) {
          for (var i = 0; i < m.file.length; ++i)
            $root.google.protobuf.FileDescriptorProto.encode(m.file[i], w.uint32(10).fork()).ldelim();
        }
        return w;
      };
      FileDescriptorSet.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.FileDescriptorSet();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              if (!(m.file && m.file.length)) m.file = [];
              m.file.push($root.google.protobuf.FileDescriptorProto.decode(r, r.uint32()));
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return FileDescriptorSet;
    })();
    protobuf.FileDescriptorProto = (function () {
      function FileDescriptorProto(p) {
        this.dependency = [];
        this.publicDependency = [];
        this.weakDependency = [];
        this.messageType = [];
        this.enumType = [];
        this.service = [];
        this.extension = [];
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      FileDescriptorProto.prototype.name = "";
      FileDescriptorProto.prototype["package"] = "";
      FileDescriptorProto.prototype.dependency = $util.emptyArray;
      FileDescriptorProto.prototype.publicDependency = $util.emptyArray;
      FileDescriptorProto.prototype.weakDependency = $util.emptyArray;
      FileDescriptorProto.prototype.messageType = $util.emptyArray;
      FileDescriptorProto.prototype.enumType = $util.emptyArray;
      FileDescriptorProto.prototype.service = $util.emptyArray;
      FileDescriptorProto.prototype.extension = $util.emptyArray;
      FileDescriptorProto.prototype.options = null;
      FileDescriptorProto.prototype.sourceCodeInfo = null;
      FileDescriptorProto.prototype.syntax = "";
      FileDescriptorProto.create = function create(properties) {
        return new FileDescriptorProto(properties);
      };
      FileDescriptorProto.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.name != null && Object.hasOwnProperty.call(m, "name")) w.uint32(10).string(m.name);
        if (m["package"] != null && Object.hasOwnProperty.call(m, "package"))
          w.uint32(18).string(m["package"]);
        if (m.dependency != null && m.dependency.length) {
          for (var i = 0; i < m.dependency.length; ++i) w.uint32(26).string(m.dependency[i]);
        }
        if (m.messageType != null && m.messageType.length) {
          for (var i = 0; i < m.messageType.length; ++i)
            $root.google.protobuf.DescriptorProto.encode(m.messageType[i], w.uint32(34).fork()).ldelim();
        }
        if (m.enumType != null && m.enumType.length) {
          for (var i = 0; i < m.enumType.length; ++i)
            $root.google.protobuf.EnumDescriptorProto.encode(m.enumType[i], w.uint32(42).fork()).ldelim();
        }
        if (m.service != null && m.service.length) {
          for (var i = 0; i < m.service.length; ++i)
            $root.google.protobuf.ServiceDescriptorProto.encode(m.service[i], w.uint32(50).fork()).ldelim();
        }
        if (m.extension != null && m.extension.length) {
          for (var i = 0; i < m.extension.length; ++i)
            $root.google.protobuf.FieldDescriptorProto.encode(m.extension[i], w.uint32(58).fork()).ldelim();
        }
        if (m.options != null && Object.hasOwnProperty.call(m, "options"))
          $root.google.protobuf.FileOptions.encode(m.options, w.uint32(66).fork()).ldelim();
        if (m.sourceCodeInfo != null && Object.hasOwnProperty.call(m, "sourceCodeInfo"))
          $root.google.protobuf.SourceCodeInfo.encode(m.sourceCodeInfo, w.uint32(74).fork()).ldelim();
        if (m.publicDependency != null && m.publicDependency.length) {
          for (var i = 0; i < m.publicDependency.length; ++i) w.uint32(80).int32(m.publicDependency[i]);
        }
        if (m.weakDependency != null && m.weakDependency.length) {
          for (var i = 0; i < m.weakDependency.length; ++i) w.uint32(88).int32(m.weakDependency[i]);
        }
        if (m.syntax != null && Object.hasOwnProperty.call(m, "syntax")) w.uint32(98).string(m.syntax);
        return w;
      };
      FileDescriptorProto.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.FileDescriptorProto();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              m.name = r.string();
              break;
            case 2:
              m["package"] = r.string();
              break;
            case 3:
              if (!(m.dependency && m.dependency.length)) m.dependency = [];
              m.dependency.push(r.string());
              break;
            case 10:
              if (!(m.publicDependency && m.publicDependency.length)) m.publicDependency = [];
              if ((t & 7) === 2) {
                var c2 = r.uint32() + r.pos;
                while (r.pos < c2) m.publicDependency.push(r.int32());
              } else m.publicDependency.push(r.int32());
              break;
            case 11:
              if (!(m.weakDependency && m.weakDependency.length)) m.weakDependency = [];
              if ((t & 7) === 2) {
                var c2 = r.uint32() + r.pos;
                while (r.pos < c2) m.weakDependency.push(r.int32());
              } else m.weakDependency.push(r.int32());
              break;
            case 4:
              if (!(m.messageType && m.messageType.length)) m.messageType = [];
              m.messageType.push($root.google.protobuf.DescriptorProto.decode(r, r.uint32()));
              break;
            case 5:
              if (!(m.enumType && m.enumType.length)) m.enumType = [];
              m.enumType.push($root.google.protobuf.EnumDescriptorProto.decode(r, r.uint32()));
              break;
            case 6:
              if (!(m.service && m.service.length)) m.service = [];
              m.service.push($root.google.protobuf.ServiceDescriptorProto.decode(r, r.uint32()));
              break;
            case 7:
              if (!(m.extension && m.extension.length)) m.extension = [];
              m.extension.push($root.google.protobuf.FieldDescriptorProto.decode(r, r.uint32()));
              break;
            case 8:
              m.options = $root.google.protobuf.FileOptions.decode(r, r.uint32());
              break;
            case 9:
              m.sourceCodeInfo = $root.google.protobuf.SourceCodeInfo.decode(r, r.uint32());
              break;
            case 12:
              m.syntax = r.string();
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return FileDescriptorProto;
    })();
    protobuf.DescriptorProto = (function () {
      function DescriptorProto(p) {
        this.field = [];
        this.extension = [];
        this.nestedType = [];
        this.enumType = [];
        this.extensionRange = [];
        this.oneofDecl = [];
        this.reservedRange = [];
        this.reservedName = [];
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      DescriptorProto.prototype.name = "";
      DescriptorProto.prototype.field = $util.emptyArray;
      DescriptorProto.prototype.extension = $util.emptyArray;
      DescriptorProto.prototype.nestedType = $util.emptyArray;
      DescriptorProto.prototype.enumType = $util.emptyArray;
      DescriptorProto.prototype.extensionRange = $util.emptyArray;
      DescriptorProto.prototype.oneofDecl = $util.emptyArray;
      DescriptorProto.prototype.options = null;
      DescriptorProto.prototype.reservedRange = $util.emptyArray;
      DescriptorProto.prototype.reservedName = $util.emptyArray;
      DescriptorProto.create = function create(properties) {
        return new DescriptorProto(properties);
      };
      DescriptorProto.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.name != null && Object.hasOwnProperty.call(m, "name")) w.uint32(10).string(m.name);
        if (m.field != null && m.field.length) {
          for (var i = 0; i < m.field.length; ++i)
            $root.google.protobuf.FieldDescriptorProto.encode(m.field[i], w.uint32(18).fork()).ldelim();
        }
        if (m.nestedType != null && m.nestedType.length) {
          for (var i = 0; i < m.nestedType.length; ++i)
            $root.google.protobuf.DescriptorProto.encode(m.nestedType[i], w.uint32(26).fork()).ldelim();
        }
        if (m.enumType != null && m.enumType.length) {
          for (var i = 0; i < m.enumType.length; ++i)
            $root.google.protobuf.EnumDescriptorProto.encode(m.enumType[i], w.uint32(34).fork()).ldelim();
        }
        if (m.extensionRange != null && m.extensionRange.length) {
          for (var i = 0; i < m.extensionRange.length; ++i)
            $root.google.protobuf.DescriptorProto.ExtensionRange.encode(
              m.extensionRange[i],
              w.uint32(42).fork(),
            ).ldelim();
        }
        if (m.extension != null && m.extension.length) {
          for (var i = 0; i < m.extension.length; ++i)
            $root.google.protobuf.FieldDescriptorProto.encode(m.extension[i], w.uint32(50).fork()).ldelim();
        }
        if (m.options != null && Object.hasOwnProperty.call(m, "options"))
          $root.google.protobuf.MessageOptions.encode(m.options, w.uint32(58).fork()).ldelim();
        if (m.oneofDecl != null && m.oneofDecl.length) {
          for (var i = 0; i < m.oneofDecl.length; ++i)
            $root.google.protobuf.OneofDescriptorProto.encode(m.oneofDecl[i], w.uint32(66).fork()).ldelim();
        }
        if (m.reservedRange != null && m.reservedRange.length) {
          for (var i = 0; i < m.reservedRange.length; ++i)
            $root.google.protobuf.DescriptorProto.ReservedRange.encode(
              m.reservedRange[i],
              w.uint32(74).fork(),
            ).ldelim();
        }
        if (m.reservedName != null && m.reservedName.length) {
          for (var i = 0; i < m.reservedName.length; ++i) w.uint32(82).string(m.reservedName[i]);
        }
        return w;
      };
      DescriptorProto.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.DescriptorProto();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              m.name = r.string();
              break;
            case 2:
              if (!(m.field && m.field.length)) m.field = [];
              m.field.push($root.google.protobuf.FieldDescriptorProto.decode(r, r.uint32()));
              break;
            case 6:
              if (!(m.extension && m.extension.length)) m.extension = [];
              m.extension.push($root.google.protobuf.FieldDescriptorProto.decode(r, r.uint32()));
              break;
            case 3:
              if (!(m.nestedType && m.nestedType.length)) m.nestedType = [];
              m.nestedType.push($root.google.protobuf.DescriptorProto.decode(r, r.uint32()));
              break;
            case 4:
              if (!(m.enumType && m.enumType.length)) m.enumType = [];
              m.enumType.push($root.google.protobuf.EnumDescriptorProto.decode(r, r.uint32()));
              break;
            case 5:
              if (!(m.extensionRange && m.extensionRange.length)) m.extensionRange = [];
              m.extensionRange.push(
                $root.google.protobuf.DescriptorProto.ExtensionRange.decode(r, r.uint32()),
              );
              break;
            case 8:
              if (!(m.oneofDecl && m.oneofDecl.length)) m.oneofDecl = [];
              m.oneofDecl.push($root.google.protobuf.OneofDescriptorProto.decode(r, r.uint32()));
              break;
            case 7:
              m.options = $root.google.protobuf.MessageOptions.decode(r, r.uint32());
              break;
            case 9:
              if (!(m.reservedRange && m.reservedRange.length)) m.reservedRange = [];
              m.reservedRange.push($root.google.protobuf.DescriptorProto.ReservedRange.decode(r, r.uint32()));
              break;
            case 10:
              if (!(m.reservedName && m.reservedName.length)) m.reservedName = [];
              m.reservedName.push(r.string());
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      DescriptorProto.ExtensionRange = (function () {
        function ExtensionRange(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        ExtensionRange.prototype.start = 0;
        ExtensionRange.prototype.end = 0;
        ExtensionRange.create = function create(properties) {
          return new ExtensionRange(properties);
        };
        ExtensionRange.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.start != null && Object.hasOwnProperty.call(m, "start")) w.uint32(8).int32(m.start);
          if (m.end != null && Object.hasOwnProperty.call(m, "end")) w.uint32(16).int32(m.end);
          return w;
        };
        ExtensionRange.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.google.protobuf.DescriptorProto.ExtensionRange();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.start = r.int32();
                break;
              case 2:
                m.end = r.int32();
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return ExtensionRange;
      })();
      DescriptorProto.ReservedRange = (function () {
        function ReservedRange(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        ReservedRange.prototype.start = 0;
        ReservedRange.prototype.end = 0;
        ReservedRange.create = function create(properties) {
          return new ReservedRange(properties);
        };
        ReservedRange.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.start != null && Object.hasOwnProperty.call(m, "start")) w.uint32(8).int32(m.start);
          if (m.end != null && Object.hasOwnProperty.call(m, "end")) w.uint32(16).int32(m.end);
          return w;
        };
        ReservedRange.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.google.protobuf.DescriptorProto.ReservedRange();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.start = r.int32();
                break;
              case 2:
                m.end = r.int32();
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return ReservedRange;
      })();
      return DescriptorProto;
    })();
    protobuf.FieldDescriptorProto = (function () {
      function FieldDescriptorProto(p) {
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      FieldDescriptorProto.prototype.name = "";
      FieldDescriptorProto.prototype.number = 0;
      FieldDescriptorProto.prototype.label = 1;
      FieldDescriptorProto.prototype.type = 1;
      FieldDescriptorProto.prototype.typeName = "";
      FieldDescriptorProto.prototype.extendee = "";
      FieldDescriptorProto.prototype.defaultValue = "";
      FieldDescriptorProto.prototype.oneofIndex = 0;
      FieldDescriptorProto.prototype.jsonName = "";
      FieldDescriptorProto.prototype.options = null;
      FieldDescriptorProto.create = function create(properties) {
        return new FieldDescriptorProto(properties);
      };
      FieldDescriptorProto.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.name != null && Object.hasOwnProperty.call(m, "name")) w.uint32(10).string(m.name);
        if (m.extendee != null && Object.hasOwnProperty.call(m, "extendee")) w.uint32(18).string(m.extendee);
        if (m.number != null && Object.hasOwnProperty.call(m, "number")) w.uint32(24).int32(m.number);
        if (m.label != null && Object.hasOwnProperty.call(m, "label")) w.uint32(32).int32(m.label);
        if (m.type != null && Object.hasOwnProperty.call(m, "type")) w.uint32(40).int32(m.type);
        if (m.typeName != null && Object.hasOwnProperty.call(m, "typeName")) w.uint32(50).string(m.typeName);
        if (m.defaultValue != null && Object.hasOwnProperty.call(m, "defaultValue"))
          w.uint32(58).string(m.defaultValue);
        if (m.options != null && Object.hasOwnProperty.call(m, "options"))
          $root.google.protobuf.FieldOptions.encode(m.options, w.uint32(66).fork()).ldelim();
        if (m.oneofIndex != null && Object.hasOwnProperty.call(m, "oneofIndex"))
          w.uint32(72).int32(m.oneofIndex);
        if (m.jsonName != null && Object.hasOwnProperty.call(m, "jsonName")) w.uint32(82).string(m.jsonName);
        return w;
      };
      FieldDescriptorProto.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.FieldDescriptorProto();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              m.name = r.string();
              break;
            case 3:
              m.number = r.int32();
              break;
            case 4:
              m.label = r.int32();
              break;
            case 5:
              m.type = r.int32();
              break;
            case 6:
              m.typeName = r.string();
              break;
            case 2:
              m.extendee = r.string();
              break;
            case 7:
              m.defaultValue = r.string();
              break;
            case 9:
              m.oneofIndex = r.int32();
              break;
            case 10:
              m.jsonName = r.string();
              break;
            case 8:
              m.options = $root.google.protobuf.FieldOptions.decode(r, r.uint32());
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      FieldDescriptorProto.Type = (function () {
        const valuesById = {},
          values = Object.create(valuesById);
        values[(valuesById[1] = "TYPE_DOUBLE")] = 1;
        values[(valuesById[2] = "TYPE_FLOAT")] = 2;
        values[(valuesById[3] = "TYPE_INT64")] = 3;
        values[(valuesById[4] = "TYPE_UINT64")] = 4;
        values[(valuesById[5] = "TYPE_INT32")] = 5;
        values[(valuesById[6] = "TYPE_FIXED64")] = 6;
        values[(valuesById[7] = "TYPE_FIXED32")] = 7;
        values[(valuesById[8] = "TYPE_BOOL")] = 8;
        values[(valuesById[9] = "TYPE_STRING")] = 9;
        values[(valuesById[10] = "TYPE_GROUP")] = 10;
        values[(valuesById[11] = "TYPE_MESSAGE")] = 11;
        values[(valuesById[12] = "TYPE_BYTES")] = 12;
        values[(valuesById[13] = "TYPE_UINT32")] = 13;
        values[(valuesById[14] = "TYPE_ENUM")] = 14;
        values[(valuesById[15] = "TYPE_SFIXED32")] = 15;
        values[(valuesById[16] = "TYPE_SFIXED64")] = 16;
        values[(valuesById[17] = "TYPE_SINT32")] = 17;
        values[(valuesById[18] = "TYPE_SINT64")] = 18;
        return values;
      })();
      FieldDescriptorProto.Label = (function () {
        const valuesById = {},
          values = Object.create(valuesById);
        values[(valuesById[1] = "LABEL_OPTIONAL")] = 1;
        values[(valuesById[2] = "LABEL_REQUIRED")] = 2;
        values[(valuesById[3] = "LABEL_REPEATED")] = 3;
        return values;
      })();
      return FieldDescriptorProto;
    })();
    protobuf.OneofDescriptorProto = (function () {
      function OneofDescriptorProto(p) {
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      OneofDescriptorProto.prototype.name = "";
      OneofDescriptorProto.prototype.options = null;
      OneofDescriptorProto.create = function create(properties) {
        return new OneofDescriptorProto(properties);
      };
      OneofDescriptorProto.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.name != null && Object.hasOwnProperty.call(m, "name")) w.uint32(10).string(m.name);
        if (m.options != null && Object.hasOwnProperty.call(m, "options"))
          $root.google.protobuf.OneofOptions.encode(m.options, w.uint32(18).fork()).ldelim();
        return w;
      };
      OneofDescriptorProto.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.OneofDescriptorProto();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              m.name = r.string();
              break;
            case 2:
              m.options = $root.google.protobuf.OneofOptions.decode(r, r.uint32());
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return OneofDescriptorProto;
    })();
    protobuf.EnumDescriptorProto = (function () {
      function EnumDescriptorProto(p) {
        this.value = [];
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      EnumDescriptorProto.prototype.name = "";
      EnumDescriptorProto.prototype.value = $util.emptyArray;
      EnumDescriptorProto.prototype.options = null;
      EnumDescriptorProto.create = function create(properties) {
        return new EnumDescriptorProto(properties);
      };
      EnumDescriptorProto.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.name != null && Object.hasOwnProperty.call(m, "name")) w.uint32(10).string(m.name);
        if (m.value != null && m.value.length) {
          for (var i = 0; i < m.value.length; ++i)
            $root.google.protobuf.EnumValueDescriptorProto.encode(m.value[i], w.uint32(18).fork()).ldelim();
        }
        if (m.options != null && Object.hasOwnProperty.call(m, "options"))
          $root.google.protobuf.EnumOptions.encode(m.options, w.uint32(26).fork()).ldelim();
        return w;
      };
      EnumDescriptorProto.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.EnumDescriptorProto();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              m.name = r.string();
              break;
            case 2:
              if (!(m.value && m.value.length)) m.value = [];
              m.value.push($root.google.protobuf.EnumValueDescriptorProto.decode(r, r.uint32()));
              break;
            case 3:
              m.options = $root.google.protobuf.EnumOptions.decode(r, r.uint32());
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return EnumDescriptorProto;
    })();
    protobuf.EnumValueDescriptorProto = (function () {
      function EnumValueDescriptorProto(p) {
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      EnumValueDescriptorProto.prototype.name = "";
      EnumValueDescriptorProto.prototype.number = 0;
      EnumValueDescriptorProto.prototype.options = null;
      EnumValueDescriptorProto.create = function create(properties) {
        return new EnumValueDescriptorProto(properties);
      };
      EnumValueDescriptorProto.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.name != null && Object.hasOwnProperty.call(m, "name")) w.uint32(10).string(m.name);
        if (m.number != null && Object.hasOwnProperty.call(m, "number")) w.uint32(16).int32(m.number);
        if (m.options != null && Object.hasOwnProperty.call(m, "options"))
          $root.google.protobuf.EnumValueOptions.encode(m.options, w.uint32(26).fork()).ldelim();
        return w;
      };
      EnumValueDescriptorProto.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.EnumValueDescriptorProto();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              m.name = r.string();
              break;
            case 2:
              m.number = r.int32();
              break;
            case 3:
              m.options = $root.google.protobuf.EnumValueOptions.decode(r, r.uint32());
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return EnumValueDescriptorProto;
    })();
    protobuf.ServiceDescriptorProto = (function () {
      function ServiceDescriptorProto(p) {
        this.method = [];
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      ServiceDescriptorProto.prototype.name = "";
      ServiceDescriptorProto.prototype.method = $util.emptyArray;
      ServiceDescriptorProto.prototype.options = null;
      ServiceDescriptorProto.create = function create(properties) {
        return new ServiceDescriptorProto(properties);
      };
      ServiceDescriptorProto.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.name != null && Object.hasOwnProperty.call(m, "name")) w.uint32(10).string(m.name);
        if (m.method != null && m.method.length) {
          for (var i = 0; i < m.method.length; ++i)
            $root.google.protobuf.MethodDescriptorProto.encode(m.method[i], w.uint32(18).fork()).ldelim();
        }
        if (m.options != null && Object.hasOwnProperty.call(m, "options"))
          $root.google.protobuf.ServiceOptions.encode(m.options, w.uint32(26).fork()).ldelim();
        return w;
      };
      ServiceDescriptorProto.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.ServiceDescriptorProto();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              m.name = r.string();
              break;
            case 2:
              if (!(m.method && m.method.length)) m.method = [];
              m.method.push($root.google.protobuf.MethodDescriptorProto.decode(r, r.uint32()));
              break;
            case 3:
              m.options = $root.google.protobuf.ServiceOptions.decode(r, r.uint32());
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return ServiceDescriptorProto;
    })();
    protobuf.MethodDescriptorProto = (function () {
      function MethodDescriptorProto(p) {
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      MethodDescriptorProto.prototype.name = "";
      MethodDescriptorProto.prototype.inputType = "";
      MethodDescriptorProto.prototype.outputType = "";
      MethodDescriptorProto.prototype.options = null;
      MethodDescriptorProto.prototype.clientStreaming = false;
      MethodDescriptorProto.prototype.serverStreaming = false;
      MethodDescriptorProto.create = function create(properties) {
        return new MethodDescriptorProto(properties);
      };
      MethodDescriptorProto.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.name != null && Object.hasOwnProperty.call(m, "name")) w.uint32(10).string(m.name);
        if (m.inputType != null && Object.hasOwnProperty.call(m, "inputType"))
          w.uint32(18).string(m.inputType);
        if (m.outputType != null && Object.hasOwnProperty.call(m, "outputType"))
          w.uint32(26).string(m.outputType);
        if (m.options != null && Object.hasOwnProperty.call(m, "options"))
          $root.google.protobuf.MethodOptions.encode(m.options, w.uint32(34).fork()).ldelim();
        if (m.clientStreaming != null && Object.hasOwnProperty.call(m, "clientStreaming"))
          w.uint32(40).bool(m.clientStreaming);
        if (m.serverStreaming != null && Object.hasOwnProperty.call(m, "serverStreaming"))
          w.uint32(48).bool(m.serverStreaming);
        return w;
      };
      MethodDescriptorProto.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.MethodDescriptorProto();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              m.name = r.string();
              break;
            case 2:
              m.inputType = r.string();
              break;
            case 3:
              m.outputType = r.string();
              break;
            case 4:
              m.options = $root.google.protobuf.MethodOptions.decode(r, r.uint32());
              break;
            case 5:
              m.clientStreaming = r.bool();
              break;
            case 6:
              m.serverStreaming = r.bool();
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return MethodDescriptorProto;
    })();
    protobuf.FileOptions = (function () {
      function FileOptions(p) {
        this.uninterpretedOption = [];
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      FileOptions.prototype.javaPackage = "";
      FileOptions.prototype.javaOuterClassname = "";
      FileOptions.prototype.javaMultipleFiles = false;
      FileOptions.prototype.javaGenerateEqualsAndHash = false;
      FileOptions.prototype.javaStringCheckUtf8 = false;
      FileOptions.prototype.optimizeFor = 1;
      FileOptions.prototype.goPackage = "";
      FileOptions.prototype.ccGenericServices = false;
      FileOptions.prototype.javaGenericServices = false;
      FileOptions.prototype.pyGenericServices = false;
      FileOptions.prototype.deprecated = false;
      FileOptions.prototype.ccEnableArenas = false;
      FileOptions.prototype.objcClassPrefix = "";
      FileOptions.prototype.csharpNamespace = "";
      FileOptions.prototype.uninterpretedOption = $util.emptyArray;
      FileOptions.create = function create(properties) {
        return new FileOptions(properties);
      };
      FileOptions.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.javaPackage != null && Object.hasOwnProperty.call(m, "javaPackage"))
          w.uint32(10).string(m.javaPackage);
        if (m.javaOuterClassname != null && Object.hasOwnProperty.call(m, "javaOuterClassname"))
          w.uint32(66).string(m.javaOuterClassname);
        if (m.optimizeFor != null && Object.hasOwnProperty.call(m, "optimizeFor"))
          w.uint32(72).int32(m.optimizeFor);
        if (m.javaMultipleFiles != null && Object.hasOwnProperty.call(m, "javaMultipleFiles"))
          w.uint32(80).bool(m.javaMultipleFiles);
        if (m.goPackage != null && Object.hasOwnProperty.call(m, "goPackage"))
          w.uint32(90).string(m.goPackage);
        if (m.ccGenericServices != null && Object.hasOwnProperty.call(m, "ccGenericServices"))
          w.uint32(128).bool(m.ccGenericServices);
        if (m.javaGenericServices != null && Object.hasOwnProperty.call(m, "javaGenericServices"))
          w.uint32(136).bool(m.javaGenericServices);
        if (m.pyGenericServices != null && Object.hasOwnProperty.call(m, "pyGenericServices"))
          w.uint32(144).bool(m.pyGenericServices);
        if (m.javaGenerateEqualsAndHash != null && Object.hasOwnProperty.call(m, "javaGenerateEqualsAndHash"))
          w.uint32(160).bool(m.javaGenerateEqualsAndHash);
        if (m.deprecated != null && Object.hasOwnProperty.call(m, "deprecated"))
          w.uint32(184).bool(m.deprecated);
        if (m.javaStringCheckUtf8 != null && Object.hasOwnProperty.call(m, "javaStringCheckUtf8"))
          w.uint32(216).bool(m.javaStringCheckUtf8);
        if (m.ccEnableArenas != null && Object.hasOwnProperty.call(m, "ccEnableArenas"))
          w.uint32(248).bool(m.ccEnableArenas);
        if (m.objcClassPrefix != null && Object.hasOwnProperty.call(m, "objcClassPrefix"))
          w.uint32(290).string(m.objcClassPrefix);
        if (m.csharpNamespace != null && Object.hasOwnProperty.call(m, "csharpNamespace"))
          w.uint32(298).string(m.csharpNamespace);
        if (m.uninterpretedOption != null && m.uninterpretedOption.length) {
          for (var i = 0; i < m.uninterpretedOption.length; ++i)
            $root.google.protobuf.UninterpretedOption.encode(
              m.uninterpretedOption[i],
              w.uint32(7994).fork(),
            ).ldelim();
        }
        return w;
      };
      FileOptions.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.FileOptions();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              m.javaPackage = r.string();
              break;
            case 8:
              m.javaOuterClassname = r.string();
              break;
            case 10:
              m.javaMultipleFiles = r.bool();
              break;
            case 20:
              m.javaGenerateEqualsAndHash = r.bool();
              break;
            case 27:
              m.javaStringCheckUtf8 = r.bool();
              break;
            case 9:
              m.optimizeFor = r.int32();
              break;
            case 11:
              m.goPackage = r.string();
              break;
            case 16:
              m.ccGenericServices = r.bool();
              break;
            case 17:
              m.javaGenericServices = r.bool();
              break;
            case 18:
              m.pyGenericServices = r.bool();
              break;
            case 23:
              m.deprecated = r.bool();
              break;
            case 31:
              m.ccEnableArenas = r.bool();
              break;
            case 36:
              m.objcClassPrefix = r.string();
              break;
            case 37:
              m.csharpNamespace = r.string();
              break;
            case 999:
              if (!(m.uninterpretedOption && m.uninterpretedOption.length)) m.uninterpretedOption = [];
              m.uninterpretedOption.push($root.google.protobuf.UninterpretedOption.decode(r, r.uint32()));
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      FileOptions.OptimizeMode = (function () {
        const valuesById = {},
          values = Object.create(valuesById);
        values[(valuesById[1] = "SPEED")] = 1;
        values[(valuesById[2] = "CODE_SIZE")] = 2;
        values[(valuesById[3] = "LITE_RUNTIME")] = 3;
        return values;
      })();
      return FileOptions;
    })();
    protobuf.MessageOptions = (function () {
      function MessageOptions(p) {
        this.uninterpretedOption = [];
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      MessageOptions.prototype.messageSetWireFormat = false;
      MessageOptions.prototype.noStandardDescriptorAccessor = false;
      MessageOptions.prototype.deprecated = false;
      MessageOptions.prototype.mapEntry = false;
      MessageOptions.prototype.uninterpretedOption = $util.emptyArray;
      MessageOptions.create = function create(properties) {
        return new MessageOptions(properties);
      };
      MessageOptions.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.messageSetWireFormat != null && Object.hasOwnProperty.call(m, "messageSetWireFormat"))
          w.uint32(8).bool(m.messageSetWireFormat);
        if (
          m.noStandardDescriptorAccessor != null &&
          Object.hasOwnProperty.call(m, "noStandardDescriptorAccessor")
        )
          w.uint32(16).bool(m.noStandardDescriptorAccessor);
        if (m.deprecated != null && Object.hasOwnProperty.call(m, "deprecated"))
          w.uint32(24).bool(m.deprecated);
        if (m.mapEntry != null && Object.hasOwnProperty.call(m, "mapEntry")) w.uint32(56).bool(m.mapEntry);
        if (m.uninterpretedOption != null && m.uninterpretedOption.length) {
          for (var i = 0; i < m.uninterpretedOption.length; ++i)
            $root.google.protobuf.UninterpretedOption.encode(
              m.uninterpretedOption[i],
              w.uint32(7994).fork(),
            ).ldelim();
        }
        return w;
      };
      MessageOptions.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.MessageOptions();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              m.messageSetWireFormat = r.bool();
              break;
            case 2:
              m.noStandardDescriptorAccessor = r.bool();
              break;
            case 3:
              m.deprecated = r.bool();
              break;
            case 7:
              m.mapEntry = r.bool();
              break;
            case 999:
              if (!(m.uninterpretedOption && m.uninterpretedOption.length)) m.uninterpretedOption = [];
              m.uninterpretedOption.push($root.google.protobuf.UninterpretedOption.decode(r, r.uint32()));
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return MessageOptions;
    })();
    protobuf.FieldOptions = (function () {
      function FieldOptions(p) {
        this.uninterpretedOption = [];
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      FieldOptions.prototype.ctype = 0;
      FieldOptions.prototype.packed = false;
      FieldOptions.prototype.jstype = 0;
      FieldOptions.prototype.lazy = false;
      FieldOptions.prototype.deprecated = false;
      FieldOptions.prototype.weak = false;
      FieldOptions.prototype.uninterpretedOption = $util.emptyArray;
      FieldOptions.create = function create(properties) {
        return new FieldOptions(properties);
      };
      FieldOptions.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.ctype != null && Object.hasOwnProperty.call(m, "ctype")) w.uint32(8).int32(m.ctype);
        if (m.packed != null && Object.hasOwnProperty.call(m, "packed")) w.uint32(16).bool(m.packed);
        if (m.deprecated != null && Object.hasOwnProperty.call(m, "deprecated"))
          w.uint32(24).bool(m.deprecated);
        if (m.lazy != null && Object.hasOwnProperty.call(m, "lazy")) w.uint32(40).bool(m.lazy);
        if (m.jstype != null && Object.hasOwnProperty.call(m, "jstype")) w.uint32(48).int32(m.jstype);
        if (m.weak != null && Object.hasOwnProperty.call(m, "weak")) w.uint32(80).bool(m.weak);
        if (m.uninterpretedOption != null && m.uninterpretedOption.length) {
          for (var i = 0; i < m.uninterpretedOption.length; ++i)
            $root.google.protobuf.UninterpretedOption.encode(
              m.uninterpretedOption[i],
              w.uint32(7994).fork(),
            ).ldelim();
        }
        return w;
      };
      FieldOptions.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.FieldOptions();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              m.ctype = r.int32();
              break;
            case 2:
              m.packed = r.bool();
              break;
            case 6:
              m.jstype = r.int32();
              break;
            case 5:
              m.lazy = r.bool();
              break;
            case 3:
              m.deprecated = r.bool();
              break;
            case 10:
              m.weak = r.bool();
              break;
            case 999:
              if (!(m.uninterpretedOption && m.uninterpretedOption.length)) m.uninterpretedOption = [];
              m.uninterpretedOption.push($root.google.protobuf.UninterpretedOption.decode(r, r.uint32()));
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      FieldOptions.CType = (function () {
        const valuesById = {},
          values = Object.create(valuesById);
        values[(valuesById[0] = "STRING")] = 0;
        values[(valuesById[1] = "CORD")] = 1;
        values[(valuesById[2] = "STRING_PIECE")] = 2;
        return values;
      })();
      FieldOptions.JSType = (function () {
        const valuesById = {},
          values = Object.create(valuesById);
        values[(valuesById[0] = "JS_NORMAL")] = 0;
        values[(valuesById[1] = "JS_STRING")] = 1;
        values[(valuesById[2] = "JS_NUMBER")] = 2;
        return values;
      })();
      return FieldOptions;
    })();
    protobuf.OneofOptions = (function () {
      function OneofOptions(p) {
        this.uninterpretedOption = [];
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      OneofOptions.prototype.uninterpretedOption = $util.emptyArray;
      OneofOptions.create = function create(properties) {
        return new OneofOptions(properties);
      };
      OneofOptions.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.uninterpretedOption != null && m.uninterpretedOption.length) {
          for (var i = 0; i < m.uninterpretedOption.length; ++i)
            $root.google.protobuf.UninterpretedOption.encode(
              m.uninterpretedOption[i],
              w.uint32(7994).fork(),
            ).ldelim();
        }
        return w;
      };
      OneofOptions.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.OneofOptions();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 999:
              if (!(m.uninterpretedOption && m.uninterpretedOption.length)) m.uninterpretedOption = [];
              m.uninterpretedOption.push($root.google.protobuf.UninterpretedOption.decode(r, r.uint32()));
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return OneofOptions;
    })();
    protobuf.EnumOptions = (function () {
      function EnumOptions(p) {
        this.uninterpretedOption = [];
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      EnumOptions.prototype.allowAlias = false;
      EnumOptions.prototype.deprecated = false;
      EnumOptions.prototype.uninterpretedOption = $util.emptyArray;
      EnumOptions.create = function create(properties) {
        return new EnumOptions(properties);
      };
      EnumOptions.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.allowAlias != null && Object.hasOwnProperty.call(m, "allowAlias"))
          w.uint32(16).bool(m.allowAlias);
        if (m.deprecated != null && Object.hasOwnProperty.call(m, "deprecated"))
          w.uint32(24).bool(m.deprecated);
        if (m.uninterpretedOption != null && m.uninterpretedOption.length) {
          for (var i = 0; i < m.uninterpretedOption.length; ++i)
            $root.google.protobuf.UninterpretedOption.encode(
              m.uninterpretedOption[i],
              w.uint32(7994).fork(),
            ).ldelim();
        }
        return w;
      };
      EnumOptions.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.EnumOptions();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 2:
              m.allowAlias = r.bool();
              break;
            case 3:
              m.deprecated = r.bool();
              break;
            case 999:
              if (!(m.uninterpretedOption && m.uninterpretedOption.length)) m.uninterpretedOption = [];
              m.uninterpretedOption.push($root.google.protobuf.UninterpretedOption.decode(r, r.uint32()));
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return EnumOptions;
    })();
    protobuf.EnumValueOptions = (function () {
      function EnumValueOptions(p) {
        this.uninterpretedOption = [];
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      EnumValueOptions.prototype.deprecated = false;
      EnumValueOptions.prototype.uninterpretedOption = $util.emptyArray;
      EnumValueOptions.create = function create(properties) {
        return new EnumValueOptions(properties);
      };
      EnumValueOptions.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.deprecated != null && Object.hasOwnProperty.call(m, "deprecated"))
          w.uint32(8).bool(m.deprecated);
        if (m.uninterpretedOption != null && m.uninterpretedOption.length) {
          for (var i = 0; i < m.uninterpretedOption.length; ++i)
            $root.google.protobuf.UninterpretedOption.encode(
              m.uninterpretedOption[i],
              w.uint32(7994).fork(),
            ).ldelim();
        }
        return w;
      };
      EnumValueOptions.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.EnumValueOptions();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              m.deprecated = r.bool();
              break;
            case 999:
              if (!(m.uninterpretedOption && m.uninterpretedOption.length)) m.uninterpretedOption = [];
              m.uninterpretedOption.push($root.google.protobuf.UninterpretedOption.decode(r, r.uint32()));
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return EnumValueOptions;
    })();
    protobuf.ServiceOptions = (function () {
      function ServiceOptions(p) {
        this.uninterpretedOption = [];
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      ServiceOptions.prototype.deprecated = false;
      ServiceOptions.prototype.uninterpretedOption = $util.emptyArray;
      ServiceOptions.create = function create(properties) {
        return new ServiceOptions(properties);
      };
      ServiceOptions.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.deprecated != null && Object.hasOwnProperty.call(m, "deprecated"))
          w.uint32(264).bool(m.deprecated);
        if (m.uninterpretedOption != null && m.uninterpretedOption.length) {
          for (var i = 0; i < m.uninterpretedOption.length; ++i)
            $root.google.protobuf.UninterpretedOption.encode(
              m.uninterpretedOption[i],
              w.uint32(7994).fork(),
            ).ldelim();
        }
        return w;
      };
      ServiceOptions.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.ServiceOptions();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 33:
              m.deprecated = r.bool();
              break;
            case 999:
              if (!(m.uninterpretedOption && m.uninterpretedOption.length)) m.uninterpretedOption = [];
              m.uninterpretedOption.push($root.google.protobuf.UninterpretedOption.decode(r, r.uint32()));
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return ServiceOptions;
    })();
    protobuf.MethodOptions = (function () {
      function MethodOptions(p) {
        this.uninterpretedOption = [];
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      MethodOptions.prototype.deprecated = false;
      MethodOptions.prototype.uninterpretedOption = $util.emptyArray;
      MethodOptions.prototype[".google.api.http"] = null;
      MethodOptions.create = function create(properties) {
        return new MethodOptions(properties);
      };
      MethodOptions.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.deprecated != null && Object.hasOwnProperty.call(m, "deprecated"))
          w.uint32(264).bool(m.deprecated);
        if (m.uninterpretedOption != null && m.uninterpretedOption.length) {
          for (var i = 0; i < m.uninterpretedOption.length; ++i)
            $root.google.protobuf.UninterpretedOption.encode(
              m.uninterpretedOption[i],
              w.uint32(7994).fork(),
            ).ldelim();
        }
        if (m[".google.api.http"] != null && Object.hasOwnProperty.call(m, ".google.api.http"))
          $root.google.api.HttpRule.encode(m[".google.api.http"], w.uint32(578365826).fork()).ldelim();
        return w;
      };
      MethodOptions.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.MethodOptions();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 33:
              m.deprecated = r.bool();
              break;
            case 999:
              if (!(m.uninterpretedOption && m.uninterpretedOption.length)) m.uninterpretedOption = [];
              m.uninterpretedOption.push($root.google.protobuf.UninterpretedOption.decode(r, r.uint32()));
              break;
            case 72295728:
              m[".google.api.http"] = $root.google.api.HttpRule.decode(r, r.uint32());
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return MethodOptions;
    })();
    protobuf.UninterpretedOption = (function () {
      function UninterpretedOption(p) {
        this.name = [];
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      UninterpretedOption.prototype.name = $util.emptyArray;
      UninterpretedOption.prototype.identifierValue = "";
      UninterpretedOption.prototype.positiveIntValue = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
      UninterpretedOption.prototype.negativeIntValue = $util.Long ? $util.Long.fromBits(0, 0, false) : 0;
      UninterpretedOption.prototype.doubleValue = 0;
      UninterpretedOption.prototype.stringValue = $util.newBuffer([]);
      UninterpretedOption.prototype.aggregateValue = "";
      UninterpretedOption.create = function create(properties) {
        return new UninterpretedOption(properties);
      };
      UninterpretedOption.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.name != null && m.name.length) {
          for (var i = 0; i < m.name.length; ++i)
            $root.google.protobuf.UninterpretedOption.NamePart.encode(
              m.name[i],
              w.uint32(18).fork(),
            ).ldelim();
        }
        if (m.identifierValue != null && Object.hasOwnProperty.call(m, "identifierValue"))
          w.uint32(26).string(m.identifierValue);
        if (m.positiveIntValue != null && Object.hasOwnProperty.call(m, "positiveIntValue"))
          w.uint32(32).uint64(m.positiveIntValue);
        if (m.negativeIntValue != null && Object.hasOwnProperty.call(m, "negativeIntValue"))
          w.uint32(40).int64(m.negativeIntValue);
        if (m.doubleValue != null && Object.hasOwnProperty.call(m, "doubleValue"))
          w.uint32(49).double(m.doubleValue);
        if (m.stringValue != null && Object.hasOwnProperty.call(m, "stringValue"))
          w.uint32(58).bytes(m.stringValue);
        if (m.aggregateValue != null && Object.hasOwnProperty.call(m, "aggregateValue"))
          w.uint32(66).string(m.aggregateValue);
        return w;
      };
      UninterpretedOption.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.UninterpretedOption();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 2:
              if (!(m.name && m.name.length)) m.name = [];
              m.name.push($root.google.protobuf.UninterpretedOption.NamePart.decode(r, r.uint32()));
              break;
            case 3:
              m.identifierValue = r.string();
              break;
            case 4:
              m.positiveIntValue = r.uint64();
              break;
            case 5:
              m.negativeIntValue = r.int64();
              break;
            case 6:
              m.doubleValue = r.double();
              break;
            case 7:
              m.stringValue = r.bytes();
              break;
            case 8:
              m.aggregateValue = r.string();
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      UninterpretedOption.NamePart = (function () {
        function NamePart(p) {
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        NamePart.prototype.namePart = "";
        NamePart.prototype.isExtension = false;
        NamePart.create = function create(properties) {
          return new NamePart(properties);
        };
        NamePart.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          w.uint32(10).string(m.namePart);
          w.uint32(16).bool(m.isExtension);
          return w;
        };
        NamePart.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.google.protobuf.UninterpretedOption.NamePart();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                m.namePart = r.string();
                break;
              case 2:
                m.isExtension = r.bool();
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          if (!m.hasOwnProperty("namePart"))
            throw $util.ProtocolError("missing required 'namePart'", { instance: m });
          if (!m.hasOwnProperty("isExtension"))
            throw $util.ProtocolError("missing required 'isExtension'", { instance: m });
          return m;
        };
        return NamePart;
      })();
      return UninterpretedOption;
    })();
    protobuf.SourceCodeInfo = (function () {
      function SourceCodeInfo(p) {
        this.location = [];
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      SourceCodeInfo.prototype.location = $util.emptyArray;
      SourceCodeInfo.create = function create(properties) {
        return new SourceCodeInfo(properties);
      };
      SourceCodeInfo.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.location != null && m.location.length) {
          for (var i = 0; i < m.location.length; ++i)
            $root.google.protobuf.SourceCodeInfo.Location.encode(m.location[i], w.uint32(10).fork()).ldelim();
        }
        return w;
      };
      SourceCodeInfo.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.SourceCodeInfo();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              if (!(m.location && m.location.length)) m.location = [];
              m.location.push($root.google.protobuf.SourceCodeInfo.Location.decode(r, r.uint32()));
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      SourceCodeInfo.Location = (function () {
        function Location(p) {
          this.path = [];
          this.span = [];
          this.leadingDetachedComments = [];
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        Location.prototype.path = $util.emptyArray;
        Location.prototype.span = $util.emptyArray;
        Location.prototype.leadingComments = "";
        Location.prototype.trailingComments = "";
        Location.prototype.leadingDetachedComments = $util.emptyArray;
        Location.create = function create(properties) {
          return new Location(properties);
        };
        Location.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.path != null && m.path.length) {
            w.uint32(10).fork();
            for (var i = 0; i < m.path.length; ++i) w.int32(m.path[i]);
            w.ldelim();
          }
          if (m.span != null && m.span.length) {
            w.uint32(18).fork();
            for (var i = 0; i < m.span.length; ++i) w.int32(m.span[i]);
            w.ldelim();
          }
          if (m.leadingComments != null && Object.hasOwnProperty.call(m, "leadingComments"))
            w.uint32(26).string(m.leadingComments);
          if (m.trailingComments != null && Object.hasOwnProperty.call(m, "trailingComments"))
            w.uint32(34).string(m.trailingComments);
          if (m.leadingDetachedComments != null && m.leadingDetachedComments.length) {
            for (var i = 0; i < m.leadingDetachedComments.length; ++i)
              w.uint32(50).string(m.leadingDetachedComments[i]);
          }
          return w;
        };
        Location.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.google.protobuf.SourceCodeInfo.Location();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                if (!(m.path && m.path.length)) m.path = [];
                if ((t & 7) === 2) {
                  var c2 = r.uint32() + r.pos;
                  while (r.pos < c2) m.path.push(r.int32());
                } else m.path.push(r.int32());
                break;
              case 2:
                if (!(m.span && m.span.length)) m.span = [];
                if ((t & 7) === 2) {
                  var c2 = r.uint32() + r.pos;
                  while (r.pos < c2) m.span.push(r.int32());
                } else m.span.push(r.int32());
                break;
              case 3:
                m.leadingComments = r.string();
                break;
              case 4:
                m.trailingComments = r.string();
                break;
              case 6:
                if (!(m.leadingDetachedComments && m.leadingDetachedComments.length))
                  m.leadingDetachedComments = [];
                m.leadingDetachedComments.push(r.string());
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return Location;
      })();
      return SourceCodeInfo;
    })();
    protobuf.GeneratedCodeInfo = (function () {
      function GeneratedCodeInfo(p) {
        this.annotation = [];
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      GeneratedCodeInfo.prototype.annotation = $util.emptyArray;
      GeneratedCodeInfo.create = function create(properties) {
        return new GeneratedCodeInfo(properties);
      };
      GeneratedCodeInfo.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.annotation != null && m.annotation.length) {
          for (var i = 0; i < m.annotation.length; ++i)
            $root.google.protobuf.GeneratedCodeInfo.Annotation.encode(
              m.annotation[i],
              w.uint32(10).fork(),
            ).ldelim();
        }
        return w;
      };
      GeneratedCodeInfo.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.protobuf.GeneratedCodeInfo();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              if (!(m.annotation && m.annotation.length)) m.annotation = [];
              m.annotation.push($root.google.protobuf.GeneratedCodeInfo.Annotation.decode(r, r.uint32()));
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      GeneratedCodeInfo.Annotation = (function () {
        function Annotation(p) {
          this.path = [];
          if (p)
            for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
              if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
        }
        Annotation.prototype.path = $util.emptyArray;
        Annotation.prototype.sourceFile = "";
        Annotation.prototype.begin = 0;
        Annotation.prototype.end = 0;
        Annotation.create = function create(properties) {
          return new Annotation(properties);
        };
        Annotation.encode = function encode(m, w) {
          if (!w) w = $Writer.create();
          if (m.path != null && m.path.length) {
            w.uint32(10).fork();
            for (var i = 0; i < m.path.length; ++i) w.int32(m.path[i]);
            w.ldelim();
          }
          if (m.sourceFile != null && Object.hasOwnProperty.call(m, "sourceFile"))
            w.uint32(18).string(m.sourceFile);
          if (m.begin != null && Object.hasOwnProperty.call(m, "begin")) w.uint32(24).int32(m.begin);
          if (m.end != null && Object.hasOwnProperty.call(m, "end")) w.uint32(32).int32(m.end);
          return w;
        };
        Annotation.decode = function decode(r, l) {
          if (!(r instanceof $Reader)) r = $Reader.create(r);
          var c = l === undefined ? r.len : r.pos + l,
            m = new $root.google.protobuf.GeneratedCodeInfo.Annotation();
          while (r.pos < c) {
            var t = r.uint32();
            switch (t >>> 3) {
              case 1:
                if (!(m.path && m.path.length)) m.path = [];
                if ((t & 7) === 2) {
                  var c2 = r.uint32() + r.pos;
                  while (r.pos < c2) m.path.push(r.int32());
                } else m.path.push(r.int32());
                break;
              case 2:
                m.sourceFile = r.string();
                break;
              case 3:
                m.begin = r.int32();
                break;
              case 4:
                m.end = r.int32();
                break;
              default:
                r.skipType(t & 7);
                break;
            }
          }
          return m;
        };
        return Annotation;
      })();
      return GeneratedCodeInfo;
    })();
    return protobuf;
  })();
  google.api = (function () {
    const api = {};
    api.Http = (function () {
      function Http(p) {
        this.rules = [];
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      Http.prototype.rules = $util.emptyArray;
      Http.create = function create(properties) {
        return new Http(properties);
      };
      Http.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.rules != null && m.rules.length) {
          for (var i = 0; i < m.rules.length; ++i)
            $root.google.api.HttpRule.encode(m.rules[i], w.uint32(10).fork()).ldelim();
        }
        return w;
      };
      Http.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.api.Http();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              if (!(m.rules && m.rules.length)) m.rules = [];
              m.rules.push($root.google.api.HttpRule.decode(r, r.uint32()));
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return Http;
    })();
    api.HttpRule = (function () {
      function HttpRule(p) {
        this.additionalBindings = [];
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      HttpRule.prototype.get = "";
      HttpRule.prototype.put = "";
      HttpRule.prototype.post = "";
      HttpRule.prototype["delete"] = "";
      HttpRule.prototype.patch = "";
      HttpRule.prototype.custom = null;
      HttpRule.prototype.selector = "";
      HttpRule.prototype.body = "";
      HttpRule.prototype.additionalBindings = $util.emptyArray;
      let $oneOfFields;
      Object.defineProperty(HttpRule.prototype, "pattern", {
        get: $util.oneOfGetter(($oneOfFields = ["get", "put", "post", "delete", "patch", "custom"])),
        set: $util.oneOfSetter($oneOfFields),
      });
      HttpRule.create = function create(properties) {
        return new HttpRule(properties);
      };
      HttpRule.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.selector != null && Object.hasOwnProperty.call(m, "selector")) w.uint32(10).string(m.selector);
        if (m.get != null && Object.hasOwnProperty.call(m, "get")) w.uint32(18).string(m.get);
        if (m.put != null && Object.hasOwnProperty.call(m, "put")) w.uint32(26).string(m.put);
        if (m.post != null && Object.hasOwnProperty.call(m, "post")) w.uint32(34).string(m.post);
        if (m["delete"] != null && Object.hasOwnProperty.call(m, "delete")) w.uint32(42).string(m["delete"]);
        if (m.patch != null && Object.hasOwnProperty.call(m, "patch")) w.uint32(50).string(m.patch);
        if (m.body != null && Object.hasOwnProperty.call(m, "body")) w.uint32(58).string(m.body);
        if (m.custom != null && Object.hasOwnProperty.call(m, "custom"))
          $root.google.api.CustomHttpPattern.encode(m.custom, w.uint32(66).fork()).ldelim();
        if (m.additionalBindings != null && m.additionalBindings.length) {
          for (var i = 0; i < m.additionalBindings.length; ++i)
            $root.google.api.HttpRule.encode(m.additionalBindings[i], w.uint32(90).fork()).ldelim();
        }
        return w;
      };
      HttpRule.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.api.HttpRule();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 2:
              m.get = r.string();
              break;
            case 3:
              m.put = r.string();
              break;
            case 4:
              m.post = r.string();
              break;
            case 5:
              m["delete"] = r.string();
              break;
            case 6:
              m.patch = r.string();
              break;
            case 8:
              m.custom = $root.google.api.CustomHttpPattern.decode(r, r.uint32());
              break;
            case 1:
              m.selector = r.string();
              break;
            case 7:
              m.body = r.string();
              break;
            case 11:
              if (!(m.additionalBindings && m.additionalBindings.length)) m.additionalBindings = [];
              m.additionalBindings.push($root.google.api.HttpRule.decode(r, r.uint32()));
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return HttpRule;
    })();
    api.CustomHttpPattern = (function () {
      function CustomHttpPattern(p) {
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      CustomHttpPattern.prototype.kind = "";
      CustomHttpPattern.prototype.path = "";
      CustomHttpPattern.create = function create(properties) {
        return new CustomHttpPattern(properties);
      };
      CustomHttpPattern.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.kind != null && Object.hasOwnProperty.call(m, "kind")) w.uint32(10).string(m.kind);
        if (m.path != null && Object.hasOwnProperty.call(m, "path")) w.uint32(18).string(m.path);
        return w;
      };
      CustomHttpPattern.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.google.api.CustomHttpPattern();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              m.kind = r.string();
              break;
            case 2:
              m.path = r.string();
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return CustomHttpPattern;
    })();
    return api;
  })();
  return google;
})();
exports.ibc = $root.ibc = (() => {
  const ibc = {};
  ibc.core = (function () {
    const core = {};
    core.channel = (function () {
      const channel = {};
      channel.v1 = (function () {
        const v1 = {};
        v1.MsgChannelOpenInit = (function () {
          function MsgChannelOpenInit(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MsgChannelOpenInit.prototype.portId = "";
          MsgChannelOpenInit.prototype.channelId = "";
          MsgChannelOpenInit.prototype.channel = null;
          MsgChannelOpenInit.prototype.signer = "";
          MsgChannelOpenInit.create = function create(properties) {
            return new MsgChannelOpenInit(properties);
          };
          MsgChannelOpenInit.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.portId != null && Object.hasOwnProperty.call(m, "portId")) w.uint32(10).string(m.portId);
            if (m.channelId != null && Object.hasOwnProperty.call(m, "channelId"))
              w.uint32(18).string(m.channelId);
            if (m.channel != null && Object.hasOwnProperty.call(m, "channel"))
              $root.ibc.core.channel.v1.Channel.encode(m.channel, w.uint32(26).fork()).ldelim();
            if (m.signer != null && Object.hasOwnProperty.call(m, "signer")) w.uint32(34).string(m.signer);
            return w;
          };
          MsgChannelOpenInit.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.MsgChannelOpenInit();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.portId = r.string();
                  break;
                case 2:
                  m.channelId = r.string();
                  break;
                case 3:
                  m.channel = $root.ibc.core.channel.v1.Channel.decode(r, r.uint32());
                  break;
                case 4:
                  m.signer = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MsgChannelOpenInit;
        })();
        v1.MsgChannelOpenTry = (function () {
          function MsgChannelOpenTry(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MsgChannelOpenTry.prototype.portId = "";
          MsgChannelOpenTry.prototype.channelId = "";
          MsgChannelOpenTry.prototype.channel = null;
          MsgChannelOpenTry.prototype.counterpartyVersion = "";
          MsgChannelOpenTry.prototype.proofInit = $util.newBuffer([]);
          MsgChannelOpenTry.prototype.proofHeight = null;
          MsgChannelOpenTry.prototype.signer = "";
          MsgChannelOpenTry.create = function create(properties) {
            return new MsgChannelOpenTry(properties);
          };
          MsgChannelOpenTry.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.portId != null && Object.hasOwnProperty.call(m, "portId")) w.uint32(10).string(m.portId);
            if (m.channelId != null && Object.hasOwnProperty.call(m, "channelId"))
              w.uint32(18).string(m.channelId);
            if (m.channel != null && Object.hasOwnProperty.call(m, "channel"))
              $root.ibc.core.channel.v1.Channel.encode(m.channel, w.uint32(26).fork()).ldelim();
            if (m.counterpartyVersion != null && Object.hasOwnProperty.call(m, "counterpartyVersion"))
              w.uint32(34).string(m.counterpartyVersion);
            if (m.proofInit != null && Object.hasOwnProperty.call(m, "proofInit"))
              w.uint32(42).bytes(m.proofInit);
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(50).fork()).ldelim();
            if (m.signer != null && Object.hasOwnProperty.call(m, "signer")) w.uint32(58).string(m.signer);
            return w;
          };
          MsgChannelOpenTry.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.MsgChannelOpenTry();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.portId = r.string();
                  break;
                case 2:
                  m.channelId = r.string();
                  break;
                case 3:
                  m.channel = $root.ibc.core.channel.v1.Channel.decode(r, r.uint32());
                  break;
                case 4:
                  m.counterpartyVersion = r.string();
                  break;
                case 5:
                  m.proofInit = r.bytes();
                  break;
                case 6:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                case 7:
                  m.signer = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MsgChannelOpenTry;
        })();
        v1.MsgChannelOpenAck = (function () {
          function MsgChannelOpenAck(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MsgChannelOpenAck.prototype.portId = "";
          MsgChannelOpenAck.prototype.channelId = "";
          MsgChannelOpenAck.prototype.counterpartyVersion = "";
          MsgChannelOpenAck.prototype.proofTry = $util.newBuffer([]);
          MsgChannelOpenAck.prototype.proofHeight = null;
          MsgChannelOpenAck.prototype.signer = "";
          MsgChannelOpenAck.create = function create(properties) {
            return new MsgChannelOpenAck(properties);
          };
          MsgChannelOpenAck.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.portId != null && Object.hasOwnProperty.call(m, "portId")) w.uint32(10).string(m.portId);
            if (m.channelId != null && Object.hasOwnProperty.call(m, "channelId"))
              w.uint32(18).string(m.channelId);
            if (m.counterpartyVersion != null && Object.hasOwnProperty.call(m, "counterpartyVersion"))
              w.uint32(26).string(m.counterpartyVersion);
            if (m.proofTry != null && Object.hasOwnProperty.call(m, "proofTry"))
              w.uint32(34).bytes(m.proofTry);
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(42).fork()).ldelim();
            if (m.signer != null && Object.hasOwnProperty.call(m, "signer")) w.uint32(50).string(m.signer);
            return w;
          };
          MsgChannelOpenAck.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.MsgChannelOpenAck();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.portId = r.string();
                  break;
                case 2:
                  m.channelId = r.string();
                  break;
                case 3:
                  m.counterpartyVersion = r.string();
                  break;
                case 4:
                  m.proofTry = r.bytes();
                  break;
                case 5:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                case 6:
                  m.signer = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MsgChannelOpenAck;
        })();
        v1.MsgChannelOpenConfirm = (function () {
          function MsgChannelOpenConfirm(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MsgChannelOpenConfirm.prototype.portId = "";
          MsgChannelOpenConfirm.prototype.channelId = "";
          MsgChannelOpenConfirm.prototype.proofAck = $util.newBuffer([]);
          MsgChannelOpenConfirm.prototype.proofHeight = null;
          MsgChannelOpenConfirm.prototype.signer = "";
          MsgChannelOpenConfirm.create = function create(properties) {
            return new MsgChannelOpenConfirm(properties);
          };
          MsgChannelOpenConfirm.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.portId != null && Object.hasOwnProperty.call(m, "portId")) w.uint32(10).string(m.portId);
            if (m.channelId != null && Object.hasOwnProperty.call(m, "channelId"))
              w.uint32(18).string(m.channelId);
            if (m.proofAck != null && Object.hasOwnProperty.call(m, "proofAck"))
              w.uint32(26).bytes(m.proofAck);
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(34).fork()).ldelim();
            if (m.signer != null && Object.hasOwnProperty.call(m, "signer")) w.uint32(42).string(m.signer);
            return w;
          };
          MsgChannelOpenConfirm.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.MsgChannelOpenConfirm();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.portId = r.string();
                  break;
                case 2:
                  m.channelId = r.string();
                  break;
                case 3:
                  m.proofAck = r.bytes();
                  break;
                case 4:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                case 5:
                  m.signer = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MsgChannelOpenConfirm;
        })();
        v1.MsgChannelCloseInit = (function () {
          function MsgChannelCloseInit(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MsgChannelCloseInit.prototype.portId = "";
          MsgChannelCloseInit.prototype.channelId = "";
          MsgChannelCloseInit.prototype.signer = "";
          MsgChannelCloseInit.create = function create(properties) {
            return new MsgChannelCloseInit(properties);
          };
          MsgChannelCloseInit.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.portId != null && Object.hasOwnProperty.call(m, "portId")) w.uint32(10).string(m.portId);
            if (m.channelId != null && Object.hasOwnProperty.call(m, "channelId"))
              w.uint32(18).string(m.channelId);
            if (m.signer != null && Object.hasOwnProperty.call(m, "signer")) w.uint32(26).string(m.signer);
            return w;
          };
          MsgChannelCloseInit.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.MsgChannelCloseInit();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.portId = r.string();
                  break;
                case 2:
                  m.channelId = r.string();
                  break;
                case 3:
                  m.signer = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MsgChannelCloseInit;
        })();
        v1.MsgChannelCloseConfirm = (function () {
          function MsgChannelCloseConfirm(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MsgChannelCloseConfirm.prototype.portId = "";
          MsgChannelCloseConfirm.prototype.channelId = "";
          MsgChannelCloseConfirm.prototype.proofInit = $util.newBuffer([]);
          MsgChannelCloseConfirm.prototype.proofHeight = null;
          MsgChannelCloseConfirm.prototype.signer = "";
          MsgChannelCloseConfirm.create = function create(properties) {
            return new MsgChannelCloseConfirm(properties);
          };
          MsgChannelCloseConfirm.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.portId != null && Object.hasOwnProperty.call(m, "portId")) w.uint32(10).string(m.portId);
            if (m.channelId != null && Object.hasOwnProperty.call(m, "channelId"))
              w.uint32(18).string(m.channelId);
            if (m.proofInit != null && Object.hasOwnProperty.call(m, "proofInit"))
              w.uint32(26).bytes(m.proofInit);
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(34).fork()).ldelim();
            if (m.signer != null && Object.hasOwnProperty.call(m, "signer")) w.uint32(42).string(m.signer);
            return w;
          };
          MsgChannelCloseConfirm.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.MsgChannelCloseConfirm();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.portId = r.string();
                  break;
                case 2:
                  m.channelId = r.string();
                  break;
                case 3:
                  m.proofInit = r.bytes();
                  break;
                case 4:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                case 5:
                  m.signer = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MsgChannelCloseConfirm;
        })();
        v1.MsgRecvPacket = (function () {
          function MsgRecvPacket(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MsgRecvPacket.prototype.packet = null;
          MsgRecvPacket.prototype.proof = $util.newBuffer([]);
          MsgRecvPacket.prototype.proofHeight = null;
          MsgRecvPacket.prototype.signer = "";
          MsgRecvPacket.create = function create(properties) {
            return new MsgRecvPacket(properties);
          };
          MsgRecvPacket.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.packet != null && Object.hasOwnProperty.call(m, "packet"))
              $root.ibc.core.channel.v1.Packet.encode(m.packet, w.uint32(10).fork()).ldelim();
            if (m.proof != null && Object.hasOwnProperty.call(m, "proof")) w.uint32(18).bytes(m.proof);
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(26).fork()).ldelim();
            if (m.signer != null && Object.hasOwnProperty.call(m, "signer")) w.uint32(34).string(m.signer);
            return w;
          };
          MsgRecvPacket.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.MsgRecvPacket();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.packet = $root.ibc.core.channel.v1.Packet.decode(r, r.uint32());
                  break;
                case 2:
                  m.proof = r.bytes();
                  break;
                case 3:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                case 4:
                  m.signer = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MsgRecvPacket;
        })();
        v1.MsgTimeout = (function () {
          function MsgTimeout(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MsgTimeout.prototype.packet = null;
          MsgTimeout.prototype.proof = $util.newBuffer([]);
          MsgTimeout.prototype.proofHeight = null;
          MsgTimeout.prototype.nextSequenceRecv = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
          MsgTimeout.prototype.signer = "";
          MsgTimeout.create = function create(properties) {
            return new MsgTimeout(properties);
          };
          MsgTimeout.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.packet != null && Object.hasOwnProperty.call(m, "packet"))
              $root.ibc.core.channel.v1.Packet.encode(m.packet, w.uint32(10).fork()).ldelim();
            if (m.proof != null && Object.hasOwnProperty.call(m, "proof")) w.uint32(18).bytes(m.proof);
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(26).fork()).ldelim();
            if (m.nextSequenceRecv != null && Object.hasOwnProperty.call(m, "nextSequenceRecv"))
              w.uint32(32).uint64(m.nextSequenceRecv);
            if (m.signer != null && Object.hasOwnProperty.call(m, "signer")) w.uint32(42).string(m.signer);
            return w;
          };
          MsgTimeout.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.MsgTimeout();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.packet = $root.ibc.core.channel.v1.Packet.decode(r, r.uint32());
                  break;
                case 2:
                  m.proof = r.bytes();
                  break;
                case 3:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                case 4:
                  m.nextSequenceRecv = r.uint64();
                  break;
                case 5:
                  m.signer = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MsgTimeout;
        })();
        v1.MsgTimeoutOnClose = (function () {
          function MsgTimeoutOnClose(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MsgTimeoutOnClose.prototype.packet = null;
          MsgTimeoutOnClose.prototype.proof = $util.newBuffer([]);
          MsgTimeoutOnClose.prototype.proofClose = $util.newBuffer([]);
          MsgTimeoutOnClose.prototype.proofHeight = null;
          MsgTimeoutOnClose.prototype.nextSequenceRecv = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
          MsgTimeoutOnClose.prototype.signer = "";
          MsgTimeoutOnClose.create = function create(properties) {
            return new MsgTimeoutOnClose(properties);
          };
          MsgTimeoutOnClose.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.packet != null && Object.hasOwnProperty.call(m, "packet"))
              $root.ibc.core.channel.v1.Packet.encode(m.packet, w.uint32(10).fork()).ldelim();
            if (m.proof != null && Object.hasOwnProperty.call(m, "proof")) w.uint32(18).bytes(m.proof);
            if (m.proofClose != null && Object.hasOwnProperty.call(m, "proofClose"))
              w.uint32(26).bytes(m.proofClose);
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(34).fork()).ldelim();
            if (m.nextSequenceRecv != null && Object.hasOwnProperty.call(m, "nextSequenceRecv"))
              w.uint32(40).uint64(m.nextSequenceRecv);
            if (m.signer != null && Object.hasOwnProperty.call(m, "signer")) w.uint32(50).string(m.signer);
            return w;
          };
          MsgTimeoutOnClose.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.MsgTimeoutOnClose();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.packet = $root.ibc.core.channel.v1.Packet.decode(r, r.uint32());
                  break;
                case 2:
                  m.proof = r.bytes();
                  break;
                case 3:
                  m.proofClose = r.bytes();
                  break;
                case 4:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                case 5:
                  m.nextSequenceRecv = r.uint64();
                  break;
                case 6:
                  m.signer = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MsgTimeoutOnClose;
        })();
        v1.MsgAcknowledgement = (function () {
          function MsgAcknowledgement(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MsgAcknowledgement.prototype.packet = null;
          MsgAcknowledgement.prototype.acknowledgement = $util.newBuffer([]);
          MsgAcknowledgement.prototype.proof = $util.newBuffer([]);
          MsgAcknowledgement.prototype.proofHeight = null;
          MsgAcknowledgement.prototype.signer = "";
          MsgAcknowledgement.create = function create(properties) {
            return new MsgAcknowledgement(properties);
          };
          MsgAcknowledgement.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.packet != null && Object.hasOwnProperty.call(m, "packet"))
              $root.ibc.core.channel.v1.Packet.encode(m.packet, w.uint32(10).fork()).ldelim();
            if (m.acknowledgement != null && Object.hasOwnProperty.call(m, "acknowledgement"))
              w.uint32(18).bytes(m.acknowledgement);
            if (m.proof != null && Object.hasOwnProperty.call(m, "proof")) w.uint32(26).bytes(m.proof);
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(34).fork()).ldelim();
            if (m.signer != null && Object.hasOwnProperty.call(m, "signer")) w.uint32(42).string(m.signer);
            return w;
          };
          MsgAcknowledgement.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.MsgAcknowledgement();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.packet = $root.ibc.core.channel.v1.Packet.decode(r, r.uint32());
                  break;
                case 2:
                  m.acknowledgement = r.bytes();
                  break;
                case 3:
                  m.proof = r.bytes();
                  break;
                case 4:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                case 5:
                  m.signer = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MsgAcknowledgement;
        })();
        v1.Channel = (function () {
          function Channel(p) {
            this.connectionHops = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          Channel.prototype.state = 0;
          Channel.prototype.ordering = 0;
          Channel.prototype.counterparty = null;
          Channel.prototype.connectionHops = $util.emptyArray;
          Channel.prototype.version = "";
          Channel.create = function create(properties) {
            return new Channel(properties);
          };
          Channel.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.state != null && Object.hasOwnProperty.call(m, "state")) w.uint32(8).int32(m.state);
            if (m.ordering != null && Object.hasOwnProperty.call(m, "ordering"))
              w.uint32(16).int32(m.ordering);
            if (m.counterparty != null && Object.hasOwnProperty.call(m, "counterparty"))
              $root.ibc.core.channel.v1.Counterparty.encode(m.counterparty, w.uint32(26).fork()).ldelim();
            if (m.connectionHops != null && m.connectionHops.length) {
              for (var i = 0; i < m.connectionHops.length; ++i) w.uint32(34).string(m.connectionHops[i]);
            }
            if (m.version != null && Object.hasOwnProperty.call(m, "version")) w.uint32(42).string(m.version);
            return w;
          };
          Channel.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.Channel();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.state = r.int32();
                  break;
                case 2:
                  m.ordering = r.int32();
                  break;
                case 3:
                  m.counterparty = $root.ibc.core.channel.v1.Counterparty.decode(r, r.uint32());
                  break;
                case 4:
                  if (!(m.connectionHops && m.connectionHops.length)) m.connectionHops = [];
                  m.connectionHops.push(r.string());
                  break;
                case 5:
                  m.version = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return Channel;
        })();
        v1.IdentifiedChannel = (function () {
          function IdentifiedChannel(p) {
            this.connectionHops = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          IdentifiedChannel.prototype.state = 0;
          IdentifiedChannel.prototype.ordering = 0;
          IdentifiedChannel.prototype.counterparty = null;
          IdentifiedChannel.prototype.connectionHops = $util.emptyArray;
          IdentifiedChannel.prototype.version = "";
          IdentifiedChannel.prototype.portId = "";
          IdentifiedChannel.prototype.channelId = "";
          IdentifiedChannel.create = function create(properties) {
            return new IdentifiedChannel(properties);
          };
          IdentifiedChannel.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.state != null && Object.hasOwnProperty.call(m, "state")) w.uint32(8).int32(m.state);
            if (m.ordering != null && Object.hasOwnProperty.call(m, "ordering"))
              w.uint32(16).int32(m.ordering);
            if (m.counterparty != null && Object.hasOwnProperty.call(m, "counterparty"))
              $root.ibc.core.channel.v1.Counterparty.encode(m.counterparty, w.uint32(26).fork()).ldelim();
            if (m.connectionHops != null && m.connectionHops.length) {
              for (var i = 0; i < m.connectionHops.length; ++i) w.uint32(34).string(m.connectionHops[i]);
            }
            if (m.version != null && Object.hasOwnProperty.call(m, "version")) w.uint32(42).string(m.version);
            if (m.portId != null && Object.hasOwnProperty.call(m, "portId")) w.uint32(50).string(m.portId);
            if (m.channelId != null && Object.hasOwnProperty.call(m, "channelId"))
              w.uint32(58).string(m.channelId);
            return w;
          };
          IdentifiedChannel.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.IdentifiedChannel();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.state = r.int32();
                  break;
                case 2:
                  m.ordering = r.int32();
                  break;
                case 3:
                  m.counterparty = $root.ibc.core.channel.v1.Counterparty.decode(r, r.uint32());
                  break;
                case 4:
                  if (!(m.connectionHops && m.connectionHops.length)) m.connectionHops = [];
                  m.connectionHops.push(r.string());
                  break;
                case 5:
                  m.version = r.string();
                  break;
                case 6:
                  m.portId = r.string();
                  break;
                case 7:
                  m.channelId = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return IdentifiedChannel;
        })();
        v1.State = (function () {
          const valuesById = {},
            values = Object.create(valuesById);
          values[(valuesById[0] = "STATE_UNINITIALIZED_UNSPECIFIED")] = 0;
          values[(valuesById[1] = "STATE_INIT")] = 1;
          values[(valuesById[2] = "STATE_TRYOPEN")] = 2;
          values[(valuesById[3] = "STATE_OPEN")] = 3;
          values[(valuesById[4] = "STATE_CLOSED")] = 4;
          return values;
        })();
        v1.Order = (function () {
          const valuesById = {},
            values = Object.create(valuesById);
          values[(valuesById[0] = "ORDER_NONE_UNSPECIFIED")] = 0;
          values[(valuesById[1] = "ORDER_UNORDERED")] = 1;
          values[(valuesById[2] = "ORDER_ORDERED")] = 2;
          return values;
        })();
        v1.Counterparty = (function () {
          function Counterparty(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          Counterparty.prototype.portId = "";
          Counterparty.prototype.channelId = "";
          Counterparty.create = function create(properties) {
            return new Counterparty(properties);
          };
          Counterparty.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.portId != null && Object.hasOwnProperty.call(m, "portId")) w.uint32(10).string(m.portId);
            if (m.channelId != null && Object.hasOwnProperty.call(m, "channelId"))
              w.uint32(18).string(m.channelId);
            return w;
          };
          Counterparty.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.Counterparty();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.portId = r.string();
                  break;
                case 2:
                  m.channelId = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return Counterparty;
        })();
        v1.Packet = (function () {
          function Packet(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          Packet.prototype.sequence = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
          Packet.prototype.sourcePort = "";
          Packet.prototype.sourceChannel = "";
          Packet.prototype.destinationPort = "";
          Packet.prototype.destinationChannel = "";
          Packet.prototype.data = $util.newBuffer([]);
          Packet.prototype.timeoutHeight = null;
          Packet.prototype.timeoutTimestamp = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
          Packet.create = function create(properties) {
            return new Packet(properties);
          };
          Packet.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.sequence != null && Object.hasOwnProperty.call(m, "sequence"))
              w.uint32(8).uint64(m.sequence);
            if (m.sourcePort != null && Object.hasOwnProperty.call(m, "sourcePort"))
              w.uint32(18).string(m.sourcePort);
            if (m.sourceChannel != null && Object.hasOwnProperty.call(m, "sourceChannel"))
              w.uint32(26).string(m.sourceChannel);
            if (m.destinationPort != null && Object.hasOwnProperty.call(m, "destinationPort"))
              w.uint32(34).string(m.destinationPort);
            if (m.destinationChannel != null && Object.hasOwnProperty.call(m, "destinationChannel"))
              w.uint32(42).string(m.destinationChannel);
            if (m.data != null && Object.hasOwnProperty.call(m, "data")) w.uint32(50).bytes(m.data);
            if (m.timeoutHeight != null && Object.hasOwnProperty.call(m, "timeoutHeight"))
              $root.ibc.core.client.v1.Height.encode(m.timeoutHeight, w.uint32(58).fork()).ldelim();
            if (m.timeoutTimestamp != null && Object.hasOwnProperty.call(m, "timeoutTimestamp"))
              w.uint32(64).uint64(m.timeoutTimestamp);
            return w;
          };
          Packet.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.Packet();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.sequence = r.uint64();
                  break;
                case 2:
                  m.sourcePort = r.string();
                  break;
                case 3:
                  m.sourceChannel = r.string();
                  break;
                case 4:
                  m.destinationPort = r.string();
                  break;
                case 5:
                  m.destinationChannel = r.string();
                  break;
                case 6:
                  m.data = r.bytes();
                  break;
                case 7:
                  m.timeoutHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                case 8:
                  m.timeoutTimestamp = r.uint64();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return Packet;
        })();
        v1.PacketAckCommitment = (function () {
          function PacketAckCommitment(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          PacketAckCommitment.prototype.portId = "";
          PacketAckCommitment.prototype.channelId = "";
          PacketAckCommitment.prototype.sequence = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
          PacketAckCommitment.prototype.hash = $util.newBuffer([]);
          PacketAckCommitment.create = function create(properties) {
            return new PacketAckCommitment(properties);
          };
          PacketAckCommitment.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.portId != null && Object.hasOwnProperty.call(m, "portId")) w.uint32(10).string(m.portId);
            if (m.channelId != null && Object.hasOwnProperty.call(m, "channelId"))
              w.uint32(18).string(m.channelId);
            if (m.sequence != null && Object.hasOwnProperty.call(m, "sequence"))
              w.uint32(24).uint64(m.sequence);
            if (m.hash != null && Object.hasOwnProperty.call(m, "hash")) w.uint32(34).bytes(m.hash);
            return w;
          };
          PacketAckCommitment.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.PacketAckCommitment();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.portId = r.string();
                  break;
                case 2:
                  m.channelId = r.string();
                  break;
                case 3:
                  m.sequence = r.uint64();
                  break;
                case 4:
                  m.hash = r.bytes();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return PacketAckCommitment;
        })();
        v1.Acknowledgement = (function () {
          function Acknowledgement(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          Acknowledgement.prototype.result = $util.newBuffer([]);
          Acknowledgement.prototype.error = "";
          let $oneOfFields;
          Object.defineProperty(Acknowledgement.prototype, "response", {
            get: $util.oneOfGetter(($oneOfFields = ["result", "error"])),
            set: $util.oneOfSetter($oneOfFields),
          });
          Acknowledgement.create = function create(properties) {
            return new Acknowledgement(properties);
          };
          Acknowledgement.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.result != null && Object.hasOwnProperty.call(m, "result")) w.uint32(170).bytes(m.result);
            if (m.error != null && Object.hasOwnProperty.call(m, "error")) w.uint32(178).string(m.error);
            return w;
          };
          Acknowledgement.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.Acknowledgement();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 21:
                  m.result = r.bytes();
                  break;
                case 22:
                  m.error = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return Acknowledgement;
        })();
        v1.Query = (function () {
          function Query(rpcImpl, requestDelimited, responseDelimited) {
            $protobuf.rpc.Service.call(this, rpcImpl, requestDelimited, responseDelimited);
          }
          (Query.prototype = Object.create($protobuf.rpc.Service.prototype)).constructor = Query;
          Query.create = function create(rpcImpl, requestDelimited, responseDelimited) {
            return new this(rpcImpl, requestDelimited, responseDelimited);
          };
          Object.defineProperty(
            (Query.prototype.channel = function channel(request, callback) {
              return this.rpcCall(
                channel,
                $root.ibc.core.channel.v1.QueryChannelRequest,
                $root.ibc.core.channel.v1.QueryChannelResponse,
                request,
                callback,
              );
            }),
            "name",
            { value: "Channel" },
          );
          Object.defineProperty(
            (Query.prototype.channels = function channels(request, callback) {
              return this.rpcCall(
                channels,
                $root.ibc.core.channel.v1.QueryChannelsRequest,
                $root.ibc.core.channel.v1.QueryChannelsResponse,
                request,
                callback,
              );
            }),
            "name",
            { value: "Channels" },
          );
          Object.defineProperty(
            (Query.prototype.connectionChannels = function connectionChannels(request, callback) {
              return this.rpcCall(
                connectionChannels,
                $root.ibc.core.channel.v1.QueryConnectionChannelsRequest,
                $root.ibc.core.channel.v1.QueryConnectionChannelsResponse,
                request,
                callback,
              );
            }),
            "name",
            { value: "ConnectionChannels" },
          );
          Object.defineProperty(
            (Query.prototype.channelClientState = function channelClientState(request, callback) {
              return this.rpcCall(
                channelClientState,
                $root.ibc.core.channel.v1.QueryChannelClientStateRequest,
                $root.ibc.core.channel.v1.QueryChannelClientStateResponse,
                request,
                callback,
              );
            }),
            "name",
            { value: "ChannelClientState" },
          );
          Object.defineProperty(
            (Query.prototype.channelConsensusState = function channelConsensusState(request, callback) {
              return this.rpcCall(
                channelConsensusState,
                $root.ibc.core.channel.v1.QueryChannelConsensusStateRequest,
                $root.ibc.core.channel.v1.QueryChannelConsensusStateResponse,
                request,
                callback,
              );
            }),
            "name",
            { value: "ChannelConsensusState" },
          );
          Object.defineProperty(
            (Query.prototype.packetCommitment = function packetCommitment(request, callback) {
              return this.rpcCall(
                packetCommitment,
                $root.ibc.core.channel.v1.QueryPacketCommitmentRequest,
                $root.ibc.core.channel.v1.QueryPacketCommitmentResponse,
                request,
                callback,
              );
            }),
            "name",
            { value: "PacketCommitment" },
          );
          Object.defineProperty(
            (Query.prototype.packetCommitments = function packetCommitments(request, callback) {
              return this.rpcCall(
                packetCommitments,
                $root.ibc.core.channel.v1.QueryPacketCommitmentsRequest,
                $root.ibc.core.channel.v1.QueryPacketCommitmentsResponse,
                request,
                callback,
              );
            }),
            "name",
            { value: "PacketCommitments" },
          );
          Object.defineProperty(
            (Query.prototype.packetAcknowledgement = function packetAcknowledgement(request, callback) {
              return this.rpcCall(
                packetAcknowledgement,
                $root.ibc.core.channel.v1.QueryPacketAcknowledgementRequest,
                $root.ibc.core.channel.v1.QueryPacketAcknowledgementResponse,
                request,
                callback,
              );
            }),
            "name",
            { value: "PacketAcknowledgement" },
          );
          Object.defineProperty(
            (Query.prototype.unreceivedPackets = function unreceivedPackets(request, callback) {
              return this.rpcCall(
                unreceivedPackets,
                $root.ibc.core.channel.v1.QueryUnreceivedPacketsRequest,
                $root.ibc.core.channel.v1.QueryUnreceivedPacketsResponse,
                request,
                callback,
              );
            }),
            "name",
            { value: "UnreceivedPackets" },
          );
          Object.defineProperty(
            (Query.prototype.unrelayedAcks = function unrelayedAcks(request, callback) {
              return this.rpcCall(
                unrelayedAcks,
                $root.ibc.core.channel.v1.QueryUnrelayedAcksRequest,
                $root.ibc.core.channel.v1.QueryUnrelayedAcksResponse,
                request,
                callback,
              );
            }),
            "name",
            { value: "UnrelayedAcks" },
          );
          Object.defineProperty(
            (Query.prototype.nextSequenceReceive = function nextSequenceReceive(request, callback) {
              return this.rpcCall(
                nextSequenceReceive,
                $root.ibc.core.channel.v1.QueryNextSequenceReceiveRequest,
                $root.ibc.core.channel.v1.QueryNextSequenceReceiveResponse,
                request,
                callback,
              );
            }),
            "name",
            { value: "NextSequenceReceive" },
          );
          return Query;
        })();
        v1.QueryChannelRequest = (function () {
          function QueryChannelRequest(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryChannelRequest.prototype.portId = "";
          QueryChannelRequest.prototype.channelId = "";
          QueryChannelRequest.create = function create(properties) {
            return new QueryChannelRequest(properties);
          };
          QueryChannelRequest.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.portId != null && Object.hasOwnProperty.call(m, "portId")) w.uint32(10).string(m.portId);
            if (m.channelId != null && Object.hasOwnProperty.call(m, "channelId"))
              w.uint32(18).string(m.channelId);
            return w;
          };
          QueryChannelRequest.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryChannelRequest();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.portId = r.string();
                  break;
                case 2:
                  m.channelId = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryChannelRequest;
        })();
        v1.QueryChannelResponse = (function () {
          function QueryChannelResponse(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryChannelResponse.prototype.channel = null;
          QueryChannelResponse.prototype.proof = $util.newBuffer([]);
          QueryChannelResponse.prototype.proofPath = "";
          QueryChannelResponse.prototype.proofHeight = null;
          QueryChannelResponse.create = function create(properties) {
            return new QueryChannelResponse(properties);
          };
          QueryChannelResponse.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.channel != null && Object.hasOwnProperty.call(m, "channel"))
              $root.ibc.core.channel.v1.Channel.encode(m.channel, w.uint32(10).fork()).ldelim();
            if (m.proof != null && Object.hasOwnProperty.call(m, "proof")) w.uint32(18).bytes(m.proof);
            if (m.proofPath != null && Object.hasOwnProperty.call(m, "proofPath"))
              w.uint32(26).string(m.proofPath);
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(34).fork()).ldelim();
            return w;
          };
          QueryChannelResponse.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryChannelResponse();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.channel = $root.ibc.core.channel.v1.Channel.decode(r, r.uint32());
                  break;
                case 2:
                  m.proof = r.bytes();
                  break;
                case 3:
                  m.proofPath = r.string();
                  break;
                case 4:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryChannelResponse;
        })();
        v1.QueryChannelsRequest = (function () {
          function QueryChannelsRequest(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryChannelsRequest.prototype.pagination = null;
          QueryChannelsRequest.create = function create(properties) {
            return new QueryChannelsRequest(properties);
          };
          QueryChannelsRequest.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.pagination != null && Object.hasOwnProperty.call(m, "pagination"))
              $root.cosmos.base.query.v1beta1.PageRequest.encode(m.pagination, w.uint32(10).fork()).ldelim();
            return w;
          };
          QueryChannelsRequest.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryChannelsRequest();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.pagination = $root.cosmos.base.query.v1beta1.PageRequest.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryChannelsRequest;
        })();
        v1.QueryChannelsResponse = (function () {
          function QueryChannelsResponse(p) {
            this.channels = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryChannelsResponse.prototype.channels = $util.emptyArray;
          QueryChannelsResponse.prototype.pagination = null;
          QueryChannelsResponse.prototype.height = null;
          QueryChannelsResponse.create = function create(properties) {
            return new QueryChannelsResponse(properties);
          };
          QueryChannelsResponse.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.channels != null && m.channels.length) {
              for (var i = 0; i < m.channels.length; ++i)
                $root.ibc.core.channel.v1.IdentifiedChannel.encode(
                  m.channels[i],
                  w.uint32(10).fork(),
                ).ldelim();
            }
            if (m.pagination != null && Object.hasOwnProperty.call(m, "pagination"))
              $root.cosmos.base.query.v1beta1.PageResponse.encode(m.pagination, w.uint32(18).fork()).ldelim();
            if (m.height != null && Object.hasOwnProperty.call(m, "height"))
              $root.ibc.core.client.v1.Height.encode(m.height, w.uint32(26).fork()).ldelim();
            return w;
          };
          QueryChannelsResponse.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryChannelsResponse();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  if (!(m.channels && m.channels.length)) m.channels = [];
                  m.channels.push($root.ibc.core.channel.v1.IdentifiedChannel.decode(r, r.uint32()));
                  break;
                case 2:
                  m.pagination = $root.cosmos.base.query.v1beta1.PageResponse.decode(r, r.uint32());
                  break;
                case 3:
                  m.height = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryChannelsResponse;
        })();
        v1.QueryConnectionChannelsRequest = (function () {
          function QueryConnectionChannelsRequest(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryConnectionChannelsRequest.prototype.connection = "";
          QueryConnectionChannelsRequest.prototype.pagination = null;
          QueryConnectionChannelsRequest.create = function create(properties) {
            return new QueryConnectionChannelsRequest(properties);
          };
          QueryConnectionChannelsRequest.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.connection != null && Object.hasOwnProperty.call(m, "connection"))
              w.uint32(10).string(m.connection);
            if (m.pagination != null && Object.hasOwnProperty.call(m, "pagination"))
              $root.cosmos.base.query.v1beta1.PageRequest.encode(m.pagination, w.uint32(18).fork()).ldelim();
            return w;
          };
          QueryConnectionChannelsRequest.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryConnectionChannelsRequest();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.connection = r.string();
                  break;
                case 2:
                  m.pagination = $root.cosmos.base.query.v1beta1.PageRequest.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryConnectionChannelsRequest;
        })();
        v1.QueryConnectionChannelsResponse = (function () {
          function QueryConnectionChannelsResponse(p) {
            this.channels = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryConnectionChannelsResponse.prototype.channels = $util.emptyArray;
          QueryConnectionChannelsResponse.prototype.pagination = null;
          QueryConnectionChannelsResponse.prototype.height = null;
          QueryConnectionChannelsResponse.create = function create(properties) {
            return new QueryConnectionChannelsResponse(properties);
          };
          QueryConnectionChannelsResponse.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.channels != null && m.channels.length) {
              for (var i = 0; i < m.channels.length; ++i)
                $root.ibc.core.channel.v1.IdentifiedChannel.encode(
                  m.channels[i],
                  w.uint32(10).fork(),
                ).ldelim();
            }
            if (m.pagination != null && Object.hasOwnProperty.call(m, "pagination"))
              $root.cosmos.base.query.v1beta1.PageResponse.encode(m.pagination, w.uint32(18).fork()).ldelim();
            if (m.height != null && Object.hasOwnProperty.call(m, "height"))
              $root.ibc.core.client.v1.Height.encode(m.height, w.uint32(26).fork()).ldelim();
            return w;
          };
          QueryConnectionChannelsResponse.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryConnectionChannelsResponse();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  if (!(m.channels && m.channels.length)) m.channels = [];
                  m.channels.push($root.ibc.core.channel.v1.IdentifiedChannel.decode(r, r.uint32()));
                  break;
                case 2:
                  m.pagination = $root.cosmos.base.query.v1beta1.PageResponse.decode(r, r.uint32());
                  break;
                case 3:
                  m.height = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryConnectionChannelsResponse;
        })();
        v1.QueryChannelClientStateRequest = (function () {
          function QueryChannelClientStateRequest(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryChannelClientStateRequest.prototype.portId = "";
          QueryChannelClientStateRequest.prototype.channelId = "";
          QueryChannelClientStateRequest.create = function create(properties) {
            return new QueryChannelClientStateRequest(properties);
          };
          QueryChannelClientStateRequest.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.portId != null && Object.hasOwnProperty.call(m, "portId")) w.uint32(10).string(m.portId);
            if (m.channelId != null && Object.hasOwnProperty.call(m, "channelId"))
              w.uint32(18).string(m.channelId);
            return w;
          };
          QueryChannelClientStateRequest.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryChannelClientStateRequest();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.portId = r.string();
                  break;
                case 2:
                  m.channelId = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryChannelClientStateRequest;
        })();
        v1.QueryChannelClientStateResponse = (function () {
          function QueryChannelClientStateResponse(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryChannelClientStateResponse.prototype.identifiedClientState = null;
          QueryChannelClientStateResponse.prototype.proof = $util.newBuffer([]);
          QueryChannelClientStateResponse.prototype.proofPath = "";
          QueryChannelClientStateResponse.prototype.proofHeight = null;
          QueryChannelClientStateResponse.create = function create(properties) {
            return new QueryChannelClientStateResponse(properties);
          };
          QueryChannelClientStateResponse.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.identifiedClientState != null && Object.hasOwnProperty.call(m, "identifiedClientState"))
              $root.ibc.core.client.v1.IdentifiedClientState.encode(
                m.identifiedClientState,
                w.uint32(10).fork(),
              ).ldelim();
            if (m.proof != null && Object.hasOwnProperty.call(m, "proof")) w.uint32(18).bytes(m.proof);
            if (m.proofPath != null && Object.hasOwnProperty.call(m, "proofPath"))
              w.uint32(26).string(m.proofPath);
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(34).fork()).ldelim();
            return w;
          };
          QueryChannelClientStateResponse.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryChannelClientStateResponse();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.identifiedClientState = $root.ibc.core.client.v1.IdentifiedClientState.decode(
                    r,
                    r.uint32(),
                  );
                  break;
                case 2:
                  m.proof = r.bytes();
                  break;
                case 3:
                  m.proofPath = r.string();
                  break;
                case 4:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryChannelClientStateResponse;
        })();
        v1.QueryChannelConsensusStateRequest = (function () {
          function QueryChannelConsensusStateRequest(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryChannelConsensusStateRequest.prototype.portId = "";
          QueryChannelConsensusStateRequest.prototype.channelId = "";
          QueryChannelConsensusStateRequest.prototype.versionNumber = $util.Long
            ? $util.Long.fromBits(0, 0, true)
            : 0;
          QueryChannelConsensusStateRequest.prototype.versionHeight = $util.Long
            ? $util.Long.fromBits(0, 0, true)
            : 0;
          QueryChannelConsensusStateRequest.create = function create(properties) {
            return new QueryChannelConsensusStateRequest(properties);
          };
          QueryChannelConsensusStateRequest.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.portId != null && Object.hasOwnProperty.call(m, "portId")) w.uint32(10).string(m.portId);
            if (m.channelId != null && Object.hasOwnProperty.call(m, "channelId"))
              w.uint32(18).string(m.channelId);
            if (m.versionNumber != null && Object.hasOwnProperty.call(m, "versionNumber"))
              w.uint32(24).uint64(m.versionNumber);
            if (m.versionHeight != null && Object.hasOwnProperty.call(m, "versionHeight"))
              w.uint32(32).uint64(m.versionHeight);
            return w;
          };
          QueryChannelConsensusStateRequest.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryChannelConsensusStateRequest();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.portId = r.string();
                  break;
                case 2:
                  m.channelId = r.string();
                  break;
                case 3:
                  m.versionNumber = r.uint64();
                  break;
                case 4:
                  m.versionHeight = r.uint64();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryChannelConsensusStateRequest;
        })();
        v1.QueryChannelConsensusStateResponse = (function () {
          function QueryChannelConsensusStateResponse(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryChannelConsensusStateResponse.prototype.consensusState = null;
          QueryChannelConsensusStateResponse.prototype.clientId = "";
          QueryChannelConsensusStateResponse.prototype.proof = $util.newBuffer([]);
          QueryChannelConsensusStateResponse.prototype.proofPath = "";
          QueryChannelConsensusStateResponse.prototype.proofHeight = null;
          QueryChannelConsensusStateResponse.create = function create(properties) {
            return new QueryChannelConsensusStateResponse(properties);
          };
          QueryChannelConsensusStateResponse.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.consensusState != null && Object.hasOwnProperty.call(m, "consensusState"))
              $root.google.protobuf.Any.encode(m.consensusState, w.uint32(10).fork()).ldelim();
            if (m.clientId != null && Object.hasOwnProperty.call(m, "clientId"))
              w.uint32(18).string(m.clientId);
            if (m.proof != null && Object.hasOwnProperty.call(m, "proof")) w.uint32(26).bytes(m.proof);
            if (m.proofPath != null && Object.hasOwnProperty.call(m, "proofPath"))
              w.uint32(34).string(m.proofPath);
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(42).fork()).ldelim();
            return w;
          };
          QueryChannelConsensusStateResponse.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryChannelConsensusStateResponse();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.consensusState = $root.google.protobuf.Any.decode(r, r.uint32());
                  break;
                case 2:
                  m.clientId = r.string();
                  break;
                case 3:
                  m.proof = r.bytes();
                  break;
                case 4:
                  m.proofPath = r.string();
                  break;
                case 5:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryChannelConsensusStateResponse;
        })();
        v1.QueryPacketCommitmentRequest = (function () {
          function QueryPacketCommitmentRequest(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryPacketCommitmentRequest.prototype.portId = "";
          QueryPacketCommitmentRequest.prototype.channelId = "";
          QueryPacketCommitmentRequest.prototype.sequence = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
          QueryPacketCommitmentRequest.create = function create(properties) {
            return new QueryPacketCommitmentRequest(properties);
          };
          QueryPacketCommitmentRequest.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.portId != null && Object.hasOwnProperty.call(m, "portId")) w.uint32(10).string(m.portId);
            if (m.channelId != null && Object.hasOwnProperty.call(m, "channelId"))
              w.uint32(18).string(m.channelId);
            if (m.sequence != null && Object.hasOwnProperty.call(m, "sequence"))
              w.uint32(24).uint64(m.sequence);
            return w;
          };
          QueryPacketCommitmentRequest.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryPacketCommitmentRequest();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.portId = r.string();
                  break;
                case 2:
                  m.channelId = r.string();
                  break;
                case 3:
                  m.sequence = r.uint64();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryPacketCommitmentRequest;
        })();
        v1.QueryPacketCommitmentResponse = (function () {
          function QueryPacketCommitmentResponse(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryPacketCommitmentResponse.prototype.commitment = $util.newBuffer([]);
          QueryPacketCommitmentResponse.prototype.proof = $util.newBuffer([]);
          QueryPacketCommitmentResponse.prototype.proofPath = "";
          QueryPacketCommitmentResponse.prototype.proofHeight = null;
          QueryPacketCommitmentResponse.create = function create(properties) {
            return new QueryPacketCommitmentResponse(properties);
          };
          QueryPacketCommitmentResponse.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.commitment != null && Object.hasOwnProperty.call(m, "commitment"))
              w.uint32(10).bytes(m.commitment);
            if (m.proof != null && Object.hasOwnProperty.call(m, "proof")) w.uint32(18).bytes(m.proof);
            if (m.proofPath != null && Object.hasOwnProperty.call(m, "proofPath"))
              w.uint32(26).string(m.proofPath);
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(34).fork()).ldelim();
            return w;
          };
          QueryPacketCommitmentResponse.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryPacketCommitmentResponse();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.commitment = r.bytes();
                  break;
                case 2:
                  m.proof = r.bytes();
                  break;
                case 3:
                  m.proofPath = r.string();
                  break;
                case 4:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryPacketCommitmentResponse;
        })();
        v1.QueryPacketCommitmentsRequest = (function () {
          function QueryPacketCommitmentsRequest(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryPacketCommitmentsRequest.prototype.portId = "";
          QueryPacketCommitmentsRequest.prototype.channelId = "";
          QueryPacketCommitmentsRequest.prototype.pagination = null;
          QueryPacketCommitmentsRequest.create = function create(properties) {
            return new QueryPacketCommitmentsRequest(properties);
          };
          QueryPacketCommitmentsRequest.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.portId != null && Object.hasOwnProperty.call(m, "portId")) w.uint32(10).string(m.portId);
            if (m.channelId != null && Object.hasOwnProperty.call(m, "channelId"))
              w.uint32(18).string(m.channelId);
            if (m.pagination != null && Object.hasOwnProperty.call(m, "pagination"))
              $root.cosmos.base.query.v1beta1.PageRequest.encode(m.pagination, w.uint32(26).fork()).ldelim();
            return w;
          };
          QueryPacketCommitmentsRequest.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryPacketCommitmentsRequest();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.portId = r.string();
                  break;
                case 2:
                  m.channelId = r.string();
                  break;
                case 3:
                  m.pagination = $root.cosmos.base.query.v1beta1.PageRequest.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryPacketCommitmentsRequest;
        })();
        v1.QueryPacketCommitmentsResponse = (function () {
          function QueryPacketCommitmentsResponse(p) {
            this.commitments = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryPacketCommitmentsResponse.prototype.commitments = $util.emptyArray;
          QueryPacketCommitmentsResponse.prototype.pagination = null;
          QueryPacketCommitmentsResponse.prototype.height = null;
          QueryPacketCommitmentsResponse.create = function create(properties) {
            return new QueryPacketCommitmentsResponse(properties);
          };
          QueryPacketCommitmentsResponse.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.commitments != null && m.commitments.length) {
              for (var i = 0; i < m.commitments.length; ++i)
                $root.ibc.core.channel.v1.PacketAckCommitment.encode(
                  m.commitments[i],
                  w.uint32(10).fork(),
                ).ldelim();
            }
            if (m.pagination != null && Object.hasOwnProperty.call(m, "pagination"))
              $root.cosmos.base.query.v1beta1.PageResponse.encode(m.pagination, w.uint32(18).fork()).ldelim();
            if (m.height != null && Object.hasOwnProperty.call(m, "height"))
              $root.ibc.core.client.v1.Height.encode(m.height, w.uint32(26).fork()).ldelim();
            return w;
          };
          QueryPacketCommitmentsResponse.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryPacketCommitmentsResponse();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  if (!(m.commitments && m.commitments.length)) m.commitments = [];
                  m.commitments.push($root.ibc.core.channel.v1.PacketAckCommitment.decode(r, r.uint32()));
                  break;
                case 2:
                  m.pagination = $root.cosmos.base.query.v1beta1.PageResponse.decode(r, r.uint32());
                  break;
                case 3:
                  m.height = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryPacketCommitmentsResponse;
        })();
        v1.QueryPacketAcknowledgementRequest = (function () {
          function QueryPacketAcknowledgementRequest(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryPacketAcknowledgementRequest.prototype.portId = "";
          QueryPacketAcknowledgementRequest.prototype.channelId = "";
          QueryPacketAcknowledgementRequest.prototype.sequence = $util.Long
            ? $util.Long.fromBits(0, 0, true)
            : 0;
          QueryPacketAcknowledgementRequest.create = function create(properties) {
            return new QueryPacketAcknowledgementRequest(properties);
          };
          QueryPacketAcknowledgementRequest.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.portId != null && Object.hasOwnProperty.call(m, "portId")) w.uint32(10).string(m.portId);
            if (m.channelId != null && Object.hasOwnProperty.call(m, "channelId"))
              w.uint32(18).string(m.channelId);
            if (m.sequence != null && Object.hasOwnProperty.call(m, "sequence"))
              w.uint32(24).uint64(m.sequence);
            return w;
          };
          QueryPacketAcknowledgementRequest.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryPacketAcknowledgementRequest();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.portId = r.string();
                  break;
                case 2:
                  m.channelId = r.string();
                  break;
                case 3:
                  m.sequence = r.uint64();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryPacketAcknowledgementRequest;
        })();
        v1.QueryPacketAcknowledgementResponse = (function () {
          function QueryPacketAcknowledgementResponse(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryPacketAcknowledgementResponse.prototype.acknowledgement = $util.newBuffer([]);
          QueryPacketAcknowledgementResponse.prototype.proof = $util.newBuffer([]);
          QueryPacketAcknowledgementResponse.prototype.proofPath = "";
          QueryPacketAcknowledgementResponse.prototype.proofHeight = null;
          QueryPacketAcknowledgementResponse.create = function create(properties) {
            return new QueryPacketAcknowledgementResponse(properties);
          };
          QueryPacketAcknowledgementResponse.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.acknowledgement != null && Object.hasOwnProperty.call(m, "acknowledgement"))
              w.uint32(10).bytes(m.acknowledgement);
            if (m.proof != null && Object.hasOwnProperty.call(m, "proof")) w.uint32(18).bytes(m.proof);
            if (m.proofPath != null && Object.hasOwnProperty.call(m, "proofPath"))
              w.uint32(26).string(m.proofPath);
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(34).fork()).ldelim();
            return w;
          };
          QueryPacketAcknowledgementResponse.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryPacketAcknowledgementResponse();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.acknowledgement = r.bytes();
                  break;
                case 2:
                  m.proof = r.bytes();
                  break;
                case 3:
                  m.proofPath = r.string();
                  break;
                case 4:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryPacketAcknowledgementResponse;
        })();
        v1.QueryUnreceivedPacketsRequest = (function () {
          function QueryUnreceivedPacketsRequest(p) {
            this.packetCommitmentSequences = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryUnreceivedPacketsRequest.prototype.portId = "";
          QueryUnreceivedPacketsRequest.prototype.channelId = "";
          QueryUnreceivedPacketsRequest.prototype.packetCommitmentSequences = $util.emptyArray;
          QueryUnreceivedPacketsRequest.create = function create(properties) {
            return new QueryUnreceivedPacketsRequest(properties);
          };
          QueryUnreceivedPacketsRequest.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.portId != null && Object.hasOwnProperty.call(m, "portId")) w.uint32(10).string(m.portId);
            if (m.channelId != null && Object.hasOwnProperty.call(m, "channelId"))
              w.uint32(18).string(m.channelId);
            if (m.packetCommitmentSequences != null && m.packetCommitmentSequences.length) {
              w.uint32(26).fork();
              for (var i = 0; i < m.packetCommitmentSequences.length; ++i)
                w.uint64(m.packetCommitmentSequences[i]);
              w.ldelim();
            }
            return w;
          };
          QueryUnreceivedPacketsRequest.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryUnreceivedPacketsRequest();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.portId = r.string();
                  break;
                case 2:
                  m.channelId = r.string();
                  break;
                case 3:
                  if (!(m.packetCommitmentSequences && m.packetCommitmentSequences.length))
                    m.packetCommitmentSequences = [];
                  if ((t & 7) === 2) {
                    var c2 = r.uint32() + r.pos;
                    while (r.pos < c2) m.packetCommitmentSequences.push(r.uint64());
                  } else m.packetCommitmentSequences.push(r.uint64());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryUnreceivedPacketsRequest;
        })();
        v1.QueryUnreceivedPacketsResponse = (function () {
          function QueryUnreceivedPacketsResponse(p) {
            this.sequences = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryUnreceivedPacketsResponse.prototype.sequences = $util.emptyArray;
          QueryUnreceivedPacketsResponse.prototype.height = null;
          QueryUnreceivedPacketsResponse.create = function create(properties) {
            return new QueryUnreceivedPacketsResponse(properties);
          };
          QueryUnreceivedPacketsResponse.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.sequences != null && m.sequences.length) {
              w.uint32(10).fork();
              for (var i = 0; i < m.sequences.length; ++i) w.uint64(m.sequences[i]);
              w.ldelim();
            }
            if (m.height != null && Object.hasOwnProperty.call(m, "height"))
              $root.ibc.core.client.v1.Height.encode(m.height, w.uint32(18).fork()).ldelim();
            return w;
          };
          QueryUnreceivedPacketsResponse.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryUnreceivedPacketsResponse();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  if (!(m.sequences && m.sequences.length)) m.sequences = [];
                  if ((t & 7) === 2) {
                    var c2 = r.uint32() + r.pos;
                    while (r.pos < c2) m.sequences.push(r.uint64());
                  } else m.sequences.push(r.uint64());
                  break;
                case 2:
                  m.height = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryUnreceivedPacketsResponse;
        })();
        v1.QueryUnrelayedAcksRequest = (function () {
          function QueryUnrelayedAcksRequest(p) {
            this.packetCommitmentSequences = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryUnrelayedAcksRequest.prototype.portId = "";
          QueryUnrelayedAcksRequest.prototype.channelId = "";
          QueryUnrelayedAcksRequest.prototype.packetCommitmentSequences = $util.emptyArray;
          QueryUnrelayedAcksRequest.create = function create(properties) {
            return new QueryUnrelayedAcksRequest(properties);
          };
          QueryUnrelayedAcksRequest.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.portId != null && Object.hasOwnProperty.call(m, "portId")) w.uint32(10).string(m.portId);
            if (m.channelId != null && Object.hasOwnProperty.call(m, "channelId"))
              w.uint32(18).string(m.channelId);
            if (m.packetCommitmentSequences != null && m.packetCommitmentSequences.length) {
              w.uint32(26).fork();
              for (var i = 0; i < m.packetCommitmentSequences.length; ++i)
                w.uint64(m.packetCommitmentSequences[i]);
              w.ldelim();
            }
            return w;
          };
          QueryUnrelayedAcksRequest.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryUnrelayedAcksRequest();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.portId = r.string();
                  break;
                case 2:
                  m.channelId = r.string();
                  break;
                case 3:
                  if (!(m.packetCommitmentSequences && m.packetCommitmentSequences.length))
                    m.packetCommitmentSequences = [];
                  if ((t & 7) === 2) {
                    var c2 = r.uint32() + r.pos;
                    while (r.pos < c2) m.packetCommitmentSequences.push(r.uint64());
                  } else m.packetCommitmentSequences.push(r.uint64());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryUnrelayedAcksRequest;
        })();
        v1.QueryUnrelayedAcksResponse = (function () {
          function QueryUnrelayedAcksResponse(p) {
            this.sequences = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryUnrelayedAcksResponse.prototype.sequences = $util.emptyArray;
          QueryUnrelayedAcksResponse.prototype.height = null;
          QueryUnrelayedAcksResponse.create = function create(properties) {
            return new QueryUnrelayedAcksResponse(properties);
          };
          QueryUnrelayedAcksResponse.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.sequences != null && m.sequences.length) {
              w.uint32(10).fork();
              for (var i = 0; i < m.sequences.length; ++i) w.uint64(m.sequences[i]);
              w.ldelim();
            }
            if (m.height != null && Object.hasOwnProperty.call(m, "height"))
              $root.ibc.core.client.v1.Height.encode(m.height, w.uint32(18).fork()).ldelim();
            return w;
          };
          QueryUnrelayedAcksResponse.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryUnrelayedAcksResponse();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  if (!(m.sequences && m.sequences.length)) m.sequences = [];
                  if ((t & 7) === 2) {
                    var c2 = r.uint32() + r.pos;
                    while (r.pos < c2) m.sequences.push(r.uint64());
                  } else m.sequences.push(r.uint64());
                  break;
                case 2:
                  m.height = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryUnrelayedAcksResponse;
        })();
        v1.QueryNextSequenceReceiveRequest = (function () {
          function QueryNextSequenceReceiveRequest(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryNextSequenceReceiveRequest.prototype.portId = "";
          QueryNextSequenceReceiveRequest.prototype.channelId = "";
          QueryNextSequenceReceiveRequest.create = function create(properties) {
            return new QueryNextSequenceReceiveRequest(properties);
          };
          QueryNextSequenceReceiveRequest.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.portId != null && Object.hasOwnProperty.call(m, "portId")) w.uint32(10).string(m.portId);
            if (m.channelId != null && Object.hasOwnProperty.call(m, "channelId"))
              w.uint32(18).string(m.channelId);
            return w;
          };
          QueryNextSequenceReceiveRequest.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryNextSequenceReceiveRequest();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.portId = r.string();
                  break;
                case 2:
                  m.channelId = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryNextSequenceReceiveRequest;
        })();
        v1.QueryNextSequenceReceiveResponse = (function () {
          function QueryNextSequenceReceiveResponse(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryNextSequenceReceiveResponse.prototype.nextSequenceReceive = $util.Long
            ? $util.Long.fromBits(0, 0, true)
            : 0;
          QueryNextSequenceReceiveResponse.prototype.proof = $util.newBuffer([]);
          QueryNextSequenceReceiveResponse.prototype.proofPath = "";
          QueryNextSequenceReceiveResponse.prototype.proofHeight = null;
          QueryNextSequenceReceiveResponse.create = function create(properties) {
            return new QueryNextSequenceReceiveResponse(properties);
          };
          QueryNextSequenceReceiveResponse.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.nextSequenceReceive != null && Object.hasOwnProperty.call(m, "nextSequenceReceive"))
              w.uint32(8).uint64(m.nextSequenceReceive);
            if (m.proof != null && Object.hasOwnProperty.call(m, "proof")) w.uint32(18).bytes(m.proof);
            if (m.proofPath != null && Object.hasOwnProperty.call(m, "proofPath"))
              w.uint32(26).string(m.proofPath);
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(34).fork()).ldelim();
            return w;
          };
          QueryNextSequenceReceiveResponse.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.channel.v1.QueryNextSequenceReceiveResponse();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.nextSequenceReceive = r.uint64();
                  break;
                case 2:
                  m.proof = r.bytes();
                  break;
                case 3:
                  m.proofPath = r.string();
                  break;
                case 4:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryNextSequenceReceiveResponse;
        })();
        return v1;
      })();
      return channel;
    })();
    core.client = (function () {
      const client = {};
      client.v1 = (function () {
        const v1 = {};
        v1.IdentifiedClientState = (function () {
          function IdentifiedClientState(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          IdentifiedClientState.prototype.clientId = "";
          IdentifiedClientState.prototype.clientState = null;
          IdentifiedClientState.create = function create(properties) {
            return new IdentifiedClientState(properties);
          };
          IdentifiedClientState.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.clientId != null && Object.hasOwnProperty.call(m, "clientId"))
              w.uint32(10).string(m.clientId);
            if (m.clientState != null && Object.hasOwnProperty.call(m, "clientState"))
              $root.google.protobuf.Any.encode(m.clientState, w.uint32(18).fork()).ldelim();
            return w;
          };
          IdentifiedClientState.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.client.v1.IdentifiedClientState();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.clientId = r.string();
                  break;
                case 2:
                  m.clientState = $root.google.protobuf.Any.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return IdentifiedClientState;
        })();
        v1.ConsensusStateWithHeight = (function () {
          function ConsensusStateWithHeight(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          ConsensusStateWithHeight.prototype.height = null;
          ConsensusStateWithHeight.prototype.consensusState = null;
          ConsensusStateWithHeight.create = function create(properties) {
            return new ConsensusStateWithHeight(properties);
          };
          ConsensusStateWithHeight.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.height != null && Object.hasOwnProperty.call(m, "height"))
              $root.ibc.core.client.v1.Height.encode(m.height, w.uint32(10).fork()).ldelim();
            if (m.consensusState != null && Object.hasOwnProperty.call(m, "consensusState"))
              $root.google.protobuf.Any.encode(m.consensusState, w.uint32(18).fork()).ldelim();
            return w;
          };
          ConsensusStateWithHeight.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.client.v1.ConsensusStateWithHeight();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.height = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                case 2:
                  m.consensusState = $root.google.protobuf.Any.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return ConsensusStateWithHeight;
        })();
        v1.ClientConsensusStates = (function () {
          function ClientConsensusStates(p) {
            this.consensusStates = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          ClientConsensusStates.prototype.clientId = "";
          ClientConsensusStates.prototype.consensusStates = $util.emptyArray;
          ClientConsensusStates.create = function create(properties) {
            return new ClientConsensusStates(properties);
          };
          ClientConsensusStates.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.clientId != null && Object.hasOwnProperty.call(m, "clientId"))
              w.uint32(10).string(m.clientId);
            if (m.consensusStates != null && m.consensusStates.length) {
              for (var i = 0; i < m.consensusStates.length; ++i)
                $root.ibc.core.client.v1.ConsensusStateWithHeight.encode(
                  m.consensusStates[i],
                  w.uint32(18).fork(),
                ).ldelim();
            }
            return w;
          };
          ClientConsensusStates.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.client.v1.ClientConsensusStates();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.clientId = r.string();
                  break;
                case 2:
                  if (!(m.consensusStates && m.consensusStates.length)) m.consensusStates = [];
                  m.consensusStates.push(
                    $root.ibc.core.client.v1.ConsensusStateWithHeight.decode(r, r.uint32()),
                  );
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return ClientConsensusStates;
        })();
        v1.ClientUpdateProposal = (function () {
          function ClientUpdateProposal(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          ClientUpdateProposal.prototype.title = "";
          ClientUpdateProposal.prototype.description = "";
          ClientUpdateProposal.prototype.clientId = "";
          ClientUpdateProposal.prototype.header = null;
          ClientUpdateProposal.create = function create(properties) {
            return new ClientUpdateProposal(properties);
          };
          ClientUpdateProposal.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.title != null && Object.hasOwnProperty.call(m, "title")) w.uint32(10).string(m.title);
            if (m.description != null && Object.hasOwnProperty.call(m, "description"))
              w.uint32(18).string(m.description);
            if (m.clientId != null && Object.hasOwnProperty.call(m, "clientId"))
              w.uint32(26).string(m.clientId);
            if (m.header != null && Object.hasOwnProperty.call(m, "header"))
              $root.google.protobuf.Any.encode(m.header, w.uint32(34).fork()).ldelim();
            return w;
          };
          ClientUpdateProposal.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.client.v1.ClientUpdateProposal();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.title = r.string();
                  break;
                case 2:
                  m.description = r.string();
                  break;
                case 3:
                  m.clientId = r.string();
                  break;
                case 4:
                  m.header = $root.google.protobuf.Any.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return ClientUpdateProposal;
        })();
        v1.MsgCreateClient = (function () {
          function MsgCreateClient(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MsgCreateClient.prototype.clientId = "";
          MsgCreateClient.prototype.clientState = null;
          MsgCreateClient.prototype.consensusState = null;
          MsgCreateClient.prototype.signer = "";
          MsgCreateClient.create = function create(properties) {
            return new MsgCreateClient(properties);
          };
          MsgCreateClient.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.clientId != null && Object.hasOwnProperty.call(m, "clientId"))
              w.uint32(10).string(m.clientId);
            if (m.clientState != null && Object.hasOwnProperty.call(m, "clientState"))
              $root.google.protobuf.Any.encode(m.clientState, w.uint32(18).fork()).ldelim();
            if (m.consensusState != null && Object.hasOwnProperty.call(m, "consensusState"))
              $root.google.protobuf.Any.encode(m.consensusState, w.uint32(26).fork()).ldelim();
            if (m.signer != null && Object.hasOwnProperty.call(m, "signer")) w.uint32(34).string(m.signer);
            return w;
          };
          MsgCreateClient.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.client.v1.MsgCreateClient();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.clientId = r.string();
                  break;
                case 2:
                  m.clientState = $root.google.protobuf.Any.decode(r, r.uint32());
                  break;
                case 3:
                  m.consensusState = $root.google.protobuf.Any.decode(r, r.uint32());
                  break;
                case 4:
                  m.signer = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MsgCreateClient;
        })();
        v1.MsgUpdateClient = (function () {
          function MsgUpdateClient(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MsgUpdateClient.prototype.clientId = "";
          MsgUpdateClient.prototype.header = null;
          MsgUpdateClient.prototype.signer = "";
          MsgUpdateClient.create = function create(properties) {
            return new MsgUpdateClient(properties);
          };
          MsgUpdateClient.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.clientId != null && Object.hasOwnProperty.call(m, "clientId"))
              w.uint32(10).string(m.clientId);
            if (m.header != null && Object.hasOwnProperty.call(m, "header"))
              $root.google.protobuf.Any.encode(m.header, w.uint32(18).fork()).ldelim();
            if (m.signer != null && Object.hasOwnProperty.call(m, "signer")) w.uint32(26).string(m.signer);
            return w;
          };
          MsgUpdateClient.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.client.v1.MsgUpdateClient();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.clientId = r.string();
                  break;
                case 2:
                  m.header = $root.google.protobuf.Any.decode(r, r.uint32());
                  break;
                case 3:
                  m.signer = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MsgUpdateClient;
        })();
        v1.MsgUpgradeClient = (function () {
          function MsgUpgradeClient(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MsgUpgradeClient.prototype.clientId = "";
          MsgUpgradeClient.prototype.clientState = null;
          MsgUpgradeClient.prototype.proofUpgrade = $util.newBuffer([]);
          MsgUpgradeClient.prototype.signer = "";
          MsgUpgradeClient.create = function create(properties) {
            return new MsgUpgradeClient(properties);
          };
          MsgUpgradeClient.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.clientId != null && Object.hasOwnProperty.call(m, "clientId"))
              w.uint32(10).string(m.clientId);
            if (m.clientState != null && Object.hasOwnProperty.call(m, "clientState"))
              $root.google.protobuf.Any.encode(m.clientState, w.uint32(18).fork()).ldelim();
            if (m.proofUpgrade != null && Object.hasOwnProperty.call(m, "proofUpgrade"))
              w.uint32(26).bytes(m.proofUpgrade);
            if (m.signer != null && Object.hasOwnProperty.call(m, "signer")) w.uint32(34).string(m.signer);
            return w;
          };
          MsgUpgradeClient.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.client.v1.MsgUpgradeClient();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.clientId = r.string();
                  break;
                case 2:
                  m.clientState = $root.google.protobuf.Any.decode(r, r.uint32());
                  break;
                case 3:
                  m.proofUpgrade = r.bytes();
                  break;
                case 4:
                  m.signer = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MsgUpgradeClient;
        })();
        v1.MsgSubmitMisbehaviour = (function () {
          function MsgSubmitMisbehaviour(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MsgSubmitMisbehaviour.prototype.clientId = "";
          MsgSubmitMisbehaviour.prototype.misbehaviour = null;
          MsgSubmitMisbehaviour.prototype.signer = "";
          MsgSubmitMisbehaviour.create = function create(properties) {
            return new MsgSubmitMisbehaviour(properties);
          };
          MsgSubmitMisbehaviour.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.clientId != null && Object.hasOwnProperty.call(m, "clientId"))
              w.uint32(10).string(m.clientId);
            if (m.misbehaviour != null && Object.hasOwnProperty.call(m, "misbehaviour"))
              $root.google.protobuf.Any.encode(m.misbehaviour, w.uint32(18).fork()).ldelim();
            if (m.signer != null && Object.hasOwnProperty.call(m, "signer")) w.uint32(26).string(m.signer);
            return w;
          };
          MsgSubmitMisbehaviour.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.client.v1.MsgSubmitMisbehaviour();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.clientId = r.string();
                  break;
                case 2:
                  m.misbehaviour = $root.google.protobuf.Any.decode(r, r.uint32());
                  break;
                case 3:
                  m.signer = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MsgSubmitMisbehaviour;
        })();
        v1.Height = (function () {
          function Height(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          Height.prototype.versionNumber = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
          Height.prototype.versionHeight = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
          Height.create = function create(properties) {
            return new Height(properties);
          };
          Height.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.versionNumber != null && Object.hasOwnProperty.call(m, "versionNumber"))
              w.uint32(8).uint64(m.versionNumber);
            if (m.versionHeight != null && Object.hasOwnProperty.call(m, "versionHeight"))
              w.uint32(16).uint64(m.versionHeight);
            return w;
          };
          Height.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.client.v1.Height();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.versionNumber = r.uint64();
                  break;
                case 2:
                  m.versionHeight = r.uint64();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return Height;
        })();
        return v1;
      })();
      return client;
    })();
    core.commitment = (function () {
      const commitment = {};
      commitment.v1 = (function () {
        const v1 = {};
        v1.MerkleRoot = (function () {
          function MerkleRoot(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MerkleRoot.prototype.hash = $util.newBuffer([]);
          MerkleRoot.create = function create(properties) {
            return new MerkleRoot(properties);
          };
          MerkleRoot.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.hash != null && Object.hasOwnProperty.call(m, "hash")) w.uint32(10).bytes(m.hash);
            return w;
          };
          MerkleRoot.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.commitment.v1.MerkleRoot();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.hash = r.bytes();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MerkleRoot;
        })();
        v1.MerklePrefix = (function () {
          function MerklePrefix(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MerklePrefix.prototype.keyPrefix = $util.newBuffer([]);
          MerklePrefix.create = function create(properties) {
            return new MerklePrefix(properties);
          };
          MerklePrefix.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.keyPrefix != null && Object.hasOwnProperty.call(m, "keyPrefix"))
              w.uint32(10).bytes(m.keyPrefix);
            return w;
          };
          MerklePrefix.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.commitment.v1.MerklePrefix();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.keyPrefix = r.bytes();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MerklePrefix;
        })();
        v1.MerklePath = (function () {
          function MerklePath(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MerklePath.prototype.keyPath = null;
          MerklePath.create = function create(properties) {
            return new MerklePath(properties);
          };
          MerklePath.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.keyPath != null && Object.hasOwnProperty.call(m, "keyPath"))
              $root.ibc.core.commitment.v1.KeyPath.encode(m.keyPath, w.uint32(10).fork()).ldelim();
            return w;
          };
          MerklePath.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.commitment.v1.MerklePath();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.keyPath = $root.ibc.core.commitment.v1.KeyPath.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MerklePath;
        })();
        v1.MerkleProof = (function () {
          function MerkleProof(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MerkleProof.prototype.proof = null;
          MerkleProof.create = function create(properties) {
            return new MerkleProof(properties);
          };
          MerkleProof.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.proof != null && Object.hasOwnProperty.call(m, "proof"))
              $root.tendermint.crypto.ProofOps.encode(m.proof, w.uint32(10).fork()).ldelim();
            return w;
          };
          MerkleProof.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.commitment.v1.MerkleProof();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.proof = $root.tendermint.crypto.ProofOps.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MerkleProof;
        })();
        v1.KeyPath = (function () {
          function KeyPath(p) {
            this.keys = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          KeyPath.prototype.keys = $util.emptyArray;
          KeyPath.create = function create(properties) {
            return new KeyPath(properties);
          };
          KeyPath.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.keys != null && m.keys.length) {
              for (var i = 0; i < m.keys.length; ++i)
                $root.ibc.core.commitment.v1.Key.encode(m.keys[i], w.uint32(10).fork()).ldelim();
            }
            return w;
          };
          KeyPath.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.commitment.v1.KeyPath();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  if (!(m.keys && m.keys.length)) m.keys = [];
                  m.keys.push($root.ibc.core.commitment.v1.Key.decode(r, r.uint32()));
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return KeyPath;
        })();
        v1.Key = (function () {
          function Key(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          Key.prototype.name = $util.newBuffer([]);
          Key.prototype.enc = 0;
          Key.create = function create(properties) {
            return new Key(properties);
          };
          Key.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.name != null && Object.hasOwnProperty.call(m, "name")) w.uint32(10).bytes(m.name);
            if (m.enc != null && Object.hasOwnProperty.call(m, "enc")) w.uint32(16).int32(m.enc);
            return w;
          };
          Key.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.commitment.v1.Key();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.name = r.bytes();
                  break;
                case 2:
                  m.enc = r.int32();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return Key;
        })();
        v1.KeyEncoding = (function () {
          const valuesById = {},
            values = Object.create(valuesById);
          values[(valuesById[0] = "KEY_ENCODING_URL_UNSPECIFIED")] = 0;
          values[(valuesById[1] = "KEY_ENCODING_HEX")] = 1;
          return values;
        })();
        return v1;
      })();
      return commitment;
    })();
    core.connection = (function () {
      const connection = {};
      connection.v1 = (function () {
        const v1 = {};
        v1.MsgConnectionOpenInit = (function () {
          function MsgConnectionOpenInit(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MsgConnectionOpenInit.prototype.clientId = "";
          MsgConnectionOpenInit.prototype.connectionId = "";
          MsgConnectionOpenInit.prototype.counterparty = null;
          MsgConnectionOpenInit.prototype.version = "";
          MsgConnectionOpenInit.prototype.signer = "";
          MsgConnectionOpenInit.create = function create(properties) {
            return new MsgConnectionOpenInit(properties);
          };
          MsgConnectionOpenInit.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.clientId != null && Object.hasOwnProperty.call(m, "clientId"))
              w.uint32(10).string(m.clientId);
            if (m.connectionId != null && Object.hasOwnProperty.call(m, "connectionId"))
              w.uint32(18).string(m.connectionId);
            if (m.counterparty != null && Object.hasOwnProperty.call(m, "counterparty"))
              $root.ibc.core.connection.v1.Counterparty.encode(m.counterparty, w.uint32(26).fork()).ldelim();
            if (m.version != null && Object.hasOwnProperty.call(m, "version")) w.uint32(34).string(m.version);
            if (m.signer != null && Object.hasOwnProperty.call(m, "signer")) w.uint32(42).string(m.signer);
            return w;
          };
          MsgConnectionOpenInit.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.connection.v1.MsgConnectionOpenInit();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.clientId = r.string();
                  break;
                case 2:
                  m.connectionId = r.string();
                  break;
                case 3:
                  m.counterparty = $root.ibc.core.connection.v1.Counterparty.decode(r, r.uint32());
                  break;
                case 4:
                  m.version = r.string();
                  break;
                case 5:
                  m.signer = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MsgConnectionOpenInit;
        })();
        v1.MsgConnectionOpenTry = (function () {
          function MsgConnectionOpenTry(p) {
            this.counterpartyVersions = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MsgConnectionOpenTry.prototype.clientId = "";
          MsgConnectionOpenTry.prototype.connectionId = "";
          MsgConnectionOpenTry.prototype.provedId = "";
          MsgConnectionOpenTry.prototype.clientState = null;
          MsgConnectionOpenTry.prototype.counterparty = null;
          MsgConnectionOpenTry.prototype.counterpartyVersions = $util.emptyArray;
          MsgConnectionOpenTry.prototype.proofHeight = null;
          MsgConnectionOpenTry.prototype.proofInit = $util.newBuffer([]);
          MsgConnectionOpenTry.prototype.proofClient = $util.newBuffer([]);
          MsgConnectionOpenTry.prototype.proofConsensus = $util.newBuffer([]);
          MsgConnectionOpenTry.prototype.consensusHeight = null;
          MsgConnectionOpenTry.prototype.signer = "";
          MsgConnectionOpenTry.create = function create(properties) {
            return new MsgConnectionOpenTry(properties);
          };
          MsgConnectionOpenTry.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.clientId != null && Object.hasOwnProperty.call(m, "clientId"))
              w.uint32(10).string(m.clientId);
            if (m.connectionId != null && Object.hasOwnProperty.call(m, "connectionId"))
              w.uint32(18).string(m.connectionId);
            if (m.provedId != null && Object.hasOwnProperty.call(m, "provedId"))
              w.uint32(26).string(m.provedId);
            if (m.clientState != null && Object.hasOwnProperty.call(m, "clientState"))
              $root.google.protobuf.Any.encode(m.clientState, w.uint32(34).fork()).ldelim();
            if (m.counterparty != null && Object.hasOwnProperty.call(m, "counterparty"))
              $root.ibc.core.connection.v1.Counterparty.encode(m.counterparty, w.uint32(42).fork()).ldelim();
            if (m.counterpartyVersions != null && m.counterpartyVersions.length) {
              for (var i = 0; i < m.counterpartyVersions.length; ++i)
                w.uint32(50).string(m.counterpartyVersions[i]);
            }
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(58).fork()).ldelim();
            if (m.proofInit != null && Object.hasOwnProperty.call(m, "proofInit"))
              w.uint32(66).bytes(m.proofInit);
            if (m.proofClient != null && Object.hasOwnProperty.call(m, "proofClient"))
              w.uint32(74).bytes(m.proofClient);
            if (m.proofConsensus != null && Object.hasOwnProperty.call(m, "proofConsensus"))
              w.uint32(82).bytes(m.proofConsensus);
            if (m.consensusHeight != null && Object.hasOwnProperty.call(m, "consensusHeight"))
              $root.ibc.core.client.v1.Height.encode(m.consensusHeight, w.uint32(90).fork()).ldelim();
            if (m.signer != null && Object.hasOwnProperty.call(m, "signer")) w.uint32(98).string(m.signer);
            return w;
          };
          MsgConnectionOpenTry.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.connection.v1.MsgConnectionOpenTry();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.clientId = r.string();
                  break;
                case 2:
                  m.connectionId = r.string();
                  break;
                case 3:
                  m.provedId = r.string();
                  break;
                case 4:
                  m.clientState = $root.google.protobuf.Any.decode(r, r.uint32());
                  break;
                case 5:
                  m.counterparty = $root.ibc.core.connection.v1.Counterparty.decode(r, r.uint32());
                  break;
                case 6:
                  if (!(m.counterpartyVersions && m.counterpartyVersions.length)) m.counterpartyVersions = [];
                  m.counterpartyVersions.push(r.string());
                  break;
                case 7:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                case 8:
                  m.proofInit = r.bytes();
                  break;
                case 9:
                  m.proofClient = r.bytes();
                  break;
                case 10:
                  m.proofConsensus = r.bytes();
                  break;
                case 11:
                  m.consensusHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                case 12:
                  m.signer = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MsgConnectionOpenTry;
        })();
        v1.MsgConnectionOpenAck = (function () {
          function MsgConnectionOpenAck(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MsgConnectionOpenAck.prototype.connectionId = "";
          MsgConnectionOpenAck.prototype.counterpartyConnectionId = "";
          MsgConnectionOpenAck.prototype.version = "";
          MsgConnectionOpenAck.prototype.clientState = null;
          MsgConnectionOpenAck.prototype.proofHeight = null;
          MsgConnectionOpenAck.prototype.proofTry = $util.newBuffer([]);
          MsgConnectionOpenAck.prototype.proofClient = $util.newBuffer([]);
          MsgConnectionOpenAck.prototype.proofConsensus = $util.newBuffer([]);
          MsgConnectionOpenAck.prototype.consensusHeight = null;
          MsgConnectionOpenAck.prototype.signer = "";
          MsgConnectionOpenAck.create = function create(properties) {
            return new MsgConnectionOpenAck(properties);
          };
          MsgConnectionOpenAck.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.connectionId != null && Object.hasOwnProperty.call(m, "connectionId"))
              w.uint32(10).string(m.connectionId);
            if (
              m.counterpartyConnectionId != null &&
              Object.hasOwnProperty.call(m, "counterpartyConnectionId")
            )
              w.uint32(18).string(m.counterpartyConnectionId);
            if (m.version != null && Object.hasOwnProperty.call(m, "version")) w.uint32(26).string(m.version);
            if (m.clientState != null && Object.hasOwnProperty.call(m, "clientState"))
              $root.google.protobuf.Any.encode(m.clientState, w.uint32(34).fork()).ldelim();
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(42).fork()).ldelim();
            if (m.proofTry != null && Object.hasOwnProperty.call(m, "proofTry"))
              w.uint32(50).bytes(m.proofTry);
            if (m.proofClient != null && Object.hasOwnProperty.call(m, "proofClient"))
              w.uint32(58).bytes(m.proofClient);
            if (m.proofConsensus != null && Object.hasOwnProperty.call(m, "proofConsensus"))
              w.uint32(66).bytes(m.proofConsensus);
            if (m.consensusHeight != null && Object.hasOwnProperty.call(m, "consensusHeight"))
              $root.ibc.core.client.v1.Height.encode(m.consensusHeight, w.uint32(74).fork()).ldelim();
            if (m.signer != null && Object.hasOwnProperty.call(m, "signer")) w.uint32(82).string(m.signer);
            return w;
          };
          MsgConnectionOpenAck.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.connection.v1.MsgConnectionOpenAck();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.connectionId = r.string();
                  break;
                case 2:
                  m.counterpartyConnectionId = r.string();
                  break;
                case 3:
                  m.version = r.string();
                  break;
                case 4:
                  m.clientState = $root.google.protobuf.Any.decode(r, r.uint32());
                  break;
                case 5:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                case 6:
                  m.proofTry = r.bytes();
                  break;
                case 7:
                  m.proofClient = r.bytes();
                  break;
                case 8:
                  m.proofConsensus = r.bytes();
                  break;
                case 9:
                  m.consensusHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                case 10:
                  m.signer = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MsgConnectionOpenAck;
        })();
        v1.MsgConnectionOpenConfirm = (function () {
          function MsgConnectionOpenConfirm(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          MsgConnectionOpenConfirm.prototype.connectionId = "";
          MsgConnectionOpenConfirm.prototype.proofAck = $util.newBuffer([]);
          MsgConnectionOpenConfirm.prototype.proofHeight = null;
          MsgConnectionOpenConfirm.prototype.signer = "";
          MsgConnectionOpenConfirm.create = function create(properties) {
            return new MsgConnectionOpenConfirm(properties);
          };
          MsgConnectionOpenConfirm.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.connectionId != null && Object.hasOwnProperty.call(m, "connectionId"))
              w.uint32(10).string(m.connectionId);
            if (m.proofAck != null && Object.hasOwnProperty.call(m, "proofAck"))
              w.uint32(18).bytes(m.proofAck);
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(26).fork()).ldelim();
            if (m.signer != null && Object.hasOwnProperty.call(m, "signer")) w.uint32(34).string(m.signer);
            return w;
          };
          MsgConnectionOpenConfirm.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.connection.v1.MsgConnectionOpenConfirm();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.connectionId = r.string();
                  break;
                case 2:
                  m.proofAck = r.bytes();
                  break;
                case 3:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                case 4:
                  m.signer = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return MsgConnectionOpenConfirm;
        })();
        v1.ConnectionEnd = (function () {
          function ConnectionEnd(p) {
            this.versions = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          ConnectionEnd.prototype.clientId = "";
          ConnectionEnd.prototype.versions = $util.emptyArray;
          ConnectionEnd.prototype.state = 0;
          ConnectionEnd.prototype.counterparty = null;
          ConnectionEnd.create = function create(properties) {
            return new ConnectionEnd(properties);
          };
          ConnectionEnd.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.clientId != null && Object.hasOwnProperty.call(m, "clientId"))
              w.uint32(10).string(m.clientId);
            if (m.versions != null && m.versions.length) {
              for (var i = 0; i < m.versions.length; ++i) w.uint32(18).string(m.versions[i]);
            }
            if (m.state != null && Object.hasOwnProperty.call(m, "state")) w.uint32(24).int32(m.state);
            if (m.counterparty != null && Object.hasOwnProperty.call(m, "counterparty"))
              $root.ibc.core.connection.v1.Counterparty.encode(m.counterparty, w.uint32(34).fork()).ldelim();
            return w;
          };
          ConnectionEnd.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.connection.v1.ConnectionEnd();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.clientId = r.string();
                  break;
                case 2:
                  if (!(m.versions && m.versions.length)) m.versions = [];
                  m.versions.push(r.string());
                  break;
                case 3:
                  m.state = r.int32();
                  break;
                case 4:
                  m.counterparty = $root.ibc.core.connection.v1.Counterparty.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return ConnectionEnd;
        })();
        v1.IdentifiedConnection = (function () {
          function IdentifiedConnection(p) {
            this.versions = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          IdentifiedConnection.prototype.id = "";
          IdentifiedConnection.prototype.clientId = "";
          IdentifiedConnection.prototype.versions = $util.emptyArray;
          IdentifiedConnection.prototype.state = 0;
          IdentifiedConnection.prototype.counterparty = null;
          IdentifiedConnection.create = function create(properties) {
            return new IdentifiedConnection(properties);
          };
          IdentifiedConnection.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.id != null && Object.hasOwnProperty.call(m, "id")) w.uint32(10).string(m.id);
            if (m.clientId != null && Object.hasOwnProperty.call(m, "clientId"))
              w.uint32(18).string(m.clientId);
            if (m.versions != null && m.versions.length) {
              for (var i = 0; i < m.versions.length; ++i) w.uint32(26).string(m.versions[i]);
            }
            if (m.state != null && Object.hasOwnProperty.call(m, "state")) w.uint32(32).int32(m.state);
            if (m.counterparty != null && Object.hasOwnProperty.call(m, "counterparty"))
              $root.ibc.core.connection.v1.Counterparty.encode(m.counterparty, w.uint32(42).fork()).ldelim();
            return w;
          };
          IdentifiedConnection.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.connection.v1.IdentifiedConnection();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.id = r.string();
                  break;
                case 2:
                  m.clientId = r.string();
                  break;
                case 3:
                  if (!(m.versions && m.versions.length)) m.versions = [];
                  m.versions.push(r.string());
                  break;
                case 4:
                  m.state = r.int32();
                  break;
                case 5:
                  m.counterparty = $root.ibc.core.connection.v1.Counterparty.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return IdentifiedConnection;
        })();
        v1.State = (function () {
          const valuesById = {},
            values = Object.create(valuesById);
          values[(valuesById[0] = "STATE_UNINITIALIZED_UNSPECIFIED")] = 0;
          values[(valuesById[1] = "STATE_INIT")] = 1;
          values[(valuesById[2] = "STATE_TRYOPEN")] = 2;
          values[(valuesById[3] = "STATE_OPEN")] = 3;
          return values;
        })();
        v1.Counterparty = (function () {
          function Counterparty(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          Counterparty.prototype.clientId = "";
          Counterparty.prototype.connectionId = "";
          Counterparty.prototype.prefix = null;
          Counterparty.create = function create(properties) {
            return new Counterparty(properties);
          };
          Counterparty.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.clientId != null && Object.hasOwnProperty.call(m, "clientId"))
              w.uint32(10).string(m.clientId);
            if (m.connectionId != null && Object.hasOwnProperty.call(m, "connectionId"))
              w.uint32(18).string(m.connectionId);
            if (m.prefix != null && Object.hasOwnProperty.call(m, "prefix"))
              $root.ibc.core.commitment.v1.MerklePrefix.encode(m.prefix, w.uint32(26).fork()).ldelim();
            return w;
          };
          Counterparty.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.connection.v1.Counterparty();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.clientId = r.string();
                  break;
                case 2:
                  m.connectionId = r.string();
                  break;
                case 3:
                  m.prefix = $root.ibc.core.commitment.v1.MerklePrefix.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return Counterparty;
        })();
        v1.ClientPaths = (function () {
          function ClientPaths(p) {
            this.paths = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          ClientPaths.prototype.paths = $util.emptyArray;
          ClientPaths.create = function create(properties) {
            return new ClientPaths(properties);
          };
          ClientPaths.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.paths != null && m.paths.length) {
              for (var i = 0; i < m.paths.length; ++i) w.uint32(10).string(m.paths[i]);
            }
            return w;
          };
          ClientPaths.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.connection.v1.ClientPaths();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  if (!(m.paths && m.paths.length)) m.paths = [];
                  m.paths.push(r.string());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return ClientPaths;
        })();
        v1.ConnectionPaths = (function () {
          function ConnectionPaths(p) {
            this.paths = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          ConnectionPaths.prototype.clientId = "";
          ConnectionPaths.prototype.paths = $util.emptyArray;
          ConnectionPaths.create = function create(properties) {
            return new ConnectionPaths(properties);
          };
          ConnectionPaths.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.clientId != null && Object.hasOwnProperty.call(m, "clientId"))
              w.uint32(10).string(m.clientId);
            if (m.paths != null && m.paths.length) {
              for (var i = 0; i < m.paths.length; ++i) w.uint32(18).string(m.paths[i]);
            }
            return w;
          };
          ConnectionPaths.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.connection.v1.ConnectionPaths();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.clientId = r.string();
                  break;
                case 2:
                  if (!(m.paths && m.paths.length)) m.paths = [];
                  m.paths.push(r.string());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return ConnectionPaths;
        })();
        v1.Version = (function () {
          function Version(p) {
            this.features = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          Version.prototype.identifier = "";
          Version.prototype.features = $util.emptyArray;
          Version.create = function create(properties) {
            return new Version(properties);
          };
          Version.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.identifier != null && Object.hasOwnProperty.call(m, "identifier"))
              w.uint32(10).string(m.identifier);
            if (m.features != null && m.features.length) {
              for (var i = 0; i < m.features.length; ++i) w.uint32(18).string(m.features[i]);
            }
            return w;
          };
          Version.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.connection.v1.Version();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.identifier = r.string();
                  break;
                case 2:
                  if (!(m.features && m.features.length)) m.features = [];
                  m.features.push(r.string());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return Version;
        })();
        v1.Query = (function () {
          function Query(rpcImpl, requestDelimited, responseDelimited) {
            $protobuf.rpc.Service.call(this, rpcImpl, requestDelimited, responseDelimited);
          }
          (Query.prototype = Object.create($protobuf.rpc.Service.prototype)).constructor = Query;
          Query.create = function create(rpcImpl, requestDelimited, responseDelimited) {
            return new this(rpcImpl, requestDelimited, responseDelimited);
          };
          Object.defineProperty(
            (Query.prototype.connection = function connection(request, callback) {
              return this.rpcCall(
                connection,
                $root.ibc.core.connection.v1.QueryConnectionRequest,
                $root.ibc.core.connection.v1.QueryConnectionResponse,
                request,
                callback,
              );
            }),
            "name",
            { value: "Connection" },
          );
          Object.defineProperty(
            (Query.prototype.connections = function connections(request, callback) {
              return this.rpcCall(
                connections,
                $root.ibc.core.connection.v1.QueryConnectionsRequest,
                $root.ibc.core.connection.v1.QueryConnectionsResponse,
                request,
                callback,
              );
            }),
            "name",
            { value: "Connections" },
          );
          Object.defineProperty(
            (Query.prototype.clientConnections = function clientConnections(request, callback) {
              return this.rpcCall(
                clientConnections,
                $root.ibc.core.connection.v1.QueryClientConnectionsRequest,
                $root.ibc.core.connection.v1.QueryClientConnectionsResponse,
                request,
                callback,
              );
            }),
            "name",
            { value: "ClientConnections" },
          );
          Object.defineProperty(
            (Query.prototype.connectionClientState = function connectionClientState(request, callback) {
              return this.rpcCall(
                connectionClientState,
                $root.ibc.core.connection.v1.QueryConnectionClientStateRequest,
                $root.ibc.core.connection.v1.QueryConnectionClientStateResponse,
                request,
                callback,
              );
            }),
            "name",
            { value: "ConnectionClientState" },
          );
          Object.defineProperty(
            (Query.prototype.connectionConsensusState = function connectionConsensusState(request, callback) {
              return this.rpcCall(
                connectionConsensusState,
                $root.ibc.core.connection.v1.QueryConnectionConsensusStateRequest,
                $root.ibc.core.connection.v1.QueryConnectionConsensusStateResponse,
                request,
                callback,
              );
            }),
            "name",
            { value: "ConnectionConsensusState" },
          );
          return Query;
        })();
        v1.QueryConnectionRequest = (function () {
          function QueryConnectionRequest(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryConnectionRequest.prototype.connectionId = "";
          QueryConnectionRequest.create = function create(properties) {
            return new QueryConnectionRequest(properties);
          };
          QueryConnectionRequest.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.connectionId != null && Object.hasOwnProperty.call(m, "connectionId"))
              w.uint32(10).string(m.connectionId);
            return w;
          };
          QueryConnectionRequest.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.connection.v1.QueryConnectionRequest();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.connectionId = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryConnectionRequest;
        })();
        v1.QueryConnectionResponse = (function () {
          function QueryConnectionResponse(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryConnectionResponse.prototype.connection = null;
          QueryConnectionResponse.prototype.proof = $util.newBuffer([]);
          QueryConnectionResponse.prototype.proofPath = "";
          QueryConnectionResponse.prototype.proofHeight = null;
          QueryConnectionResponse.create = function create(properties) {
            return new QueryConnectionResponse(properties);
          };
          QueryConnectionResponse.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.connection != null && Object.hasOwnProperty.call(m, "connection"))
              $root.ibc.core.connection.v1.ConnectionEnd.encode(m.connection, w.uint32(10).fork()).ldelim();
            if (m.proof != null && Object.hasOwnProperty.call(m, "proof")) w.uint32(18).bytes(m.proof);
            if (m.proofPath != null && Object.hasOwnProperty.call(m, "proofPath"))
              w.uint32(26).string(m.proofPath);
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(34).fork()).ldelim();
            return w;
          };
          QueryConnectionResponse.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.connection.v1.QueryConnectionResponse();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.connection = $root.ibc.core.connection.v1.ConnectionEnd.decode(r, r.uint32());
                  break;
                case 2:
                  m.proof = r.bytes();
                  break;
                case 3:
                  m.proofPath = r.string();
                  break;
                case 4:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryConnectionResponse;
        })();
        v1.QueryConnectionsRequest = (function () {
          function QueryConnectionsRequest(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryConnectionsRequest.prototype.pagination = null;
          QueryConnectionsRequest.create = function create(properties) {
            return new QueryConnectionsRequest(properties);
          };
          QueryConnectionsRequest.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.pagination != null && Object.hasOwnProperty.call(m, "pagination"))
              $root.cosmos.base.query.v1beta1.PageRequest.encode(m.pagination, w.uint32(10).fork()).ldelim();
            return w;
          };
          QueryConnectionsRequest.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.connection.v1.QueryConnectionsRequest();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.pagination = $root.cosmos.base.query.v1beta1.PageRequest.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryConnectionsRequest;
        })();
        v1.QueryConnectionsResponse = (function () {
          function QueryConnectionsResponse(p) {
            this.connections = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryConnectionsResponse.prototype.connections = $util.emptyArray;
          QueryConnectionsResponse.prototype.pagination = null;
          QueryConnectionsResponse.prototype.height = null;
          QueryConnectionsResponse.create = function create(properties) {
            return new QueryConnectionsResponse(properties);
          };
          QueryConnectionsResponse.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.connections != null && m.connections.length) {
              for (var i = 0; i < m.connections.length; ++i)
                $root.ibc.core.connection.v1.IdentifiedConnection.encode(
                  m.connections[i],
                  w.uint32(10).fork(),
                ).ldelim();
            }
            if (m.pagination != null && Object.hasOwnProperty.call(m, "pagination"))
              $root.cosmos.base.query.v1beta1.PageResponse.encode(m.pagination, w.uint32(18).fork()).ldelim();
            if (m.height != null && Object.hasOwnProperty.call(m, "height"))
              $root.ibc.core.client.v1.Height.encode(m.height, w.uint32(26).fork()).ldelim();
            return w;
          };
          QueryConnectionsResponse.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.connection.v1.QueryConnectionsResponse();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  if (!(m.connections && m.connections.length)) m.connections = [];
                  m.connections.push($root.ibc.core.connection.v1.IdentifiedConnection.decode(r, r.uint32()));
                  break;
                case 2:
                  m.pagination = $root.cosmos.base.query.v1beta1.PageResponse.decode(r, r.uint32());
                  break;
                case 3:
                  m.height = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryConnectionsResponse;
        })();
        v1.QueryClientConnectionsRequest = (function () {
          function QueryClientConnectionsRequest(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryClientConnectionsRequest.prototype.clientId = "";
          QueryClientConnectionsRequest.create = function create(properties) {
            return new QueryClientConnectionsRequest(properties);
          };
          QueryClientConnectionsRequest.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.clientId != null && Object.hasOwnProperty.call(m, "clientId"))
              w.uint32(10).string(m.clientId);
            return w;
          };
          QueryClientConnectionsRequest.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.connection.v1.QueryClientConnectionsRequest();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.clientId = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryClientConnectionsRequest;
        })();
        v1.QueryClientConnectionsResponse = (function () {
          function QueryClientConnectionsResponse(p) {
            this.connectionPaths = [];
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryClientConnectionsResponse.prototype.connectionPaths = $util.emptyArray;
          QueryClientConnectionsResponse.prototype.proof = $util.newBuffer([]);
          QueryClientConnectionsResponse.prototype.proofPath = "";
          QueryClientConnectionsResponse.prototype.proofHeight = null;
          QueryClientConnectionsResponse.create = function create(properties) {
            return new QueryClientConnectionsResponse(properties);
          };
          QueryClientConnectionsResponse.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.connectionPaths != null && m.connectionPaths.length) {
              for (var i = 0; i < m.connectionPaths.length; ++i) w.uint32(10).string(m.connectionPaths[i]);
            }
            if (m.proof != null && Object.hasOwnProperty.call(m, "proof")) w.uint32(18).bytes(m.proof);
            if (m.proofPath != null && Object.hasOwnProperty.call(m, "proofPath"))
              w.uint32(26).string(m.proofPath);
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(34).fork()).ldelim();
            return w;
          };
          QueryClientConnectionsResponse.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.connection.v1.QueryClientConnectionsResponse();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  if (!(m.connectionPaths && m.connectionPaths.length)) m.connectionPaths = [];
                  m.connectionPaths.push(r.string());
                  break;
                case 2:
                  m.proof = r.bytes();
                  break;
                case 3:
                  m.proofPath = r.string();
                  break;
                case 4:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryClientConnectionsResponse;
        })();
        v1.QueryConnectionClientStateRequest = (function () {
          function QueryConnectionClientStateRequest(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryConnectionClientStateRequest.prototype.connectionId = "";
          QueryConnectionClientStateRequest.create = function create(properties) {
            return new QueryConnectionClientStateRequest(properties);
          };
          QueryConnectionClientStateRequest.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.connectionId != null && Object.hasOwnProperty.call(m, "connectionId"))
              w.uint32(10).string(m.connectionId);
            return w;
          };
          QueryConnectionClientStateRequest.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.connection.v1.QueryConnectionClientStateRequest();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.connectionId = r.string();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryConnectionClientStateRequest;
        })();
        v1.QueryConnectionClientStateResponse = (function () {
          function QueryConnectionClientStateResponse(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryConnectionClientStateResponse.prototype.identifiedClientState = null;
          QueryConnectionClientStateResponse.prototype.proof = $util.newBuffer([]);
          QueryConnectionClientStateResponse.prototype.proofPath = "";
          QueryConnectionClientStateResponse.prototype.proofHeight = null;
          QueryConnectionClientStateResponse.create = function create(properties) {
            return new QueryConnectionClientStateResponse(properties);
          };
          QueryConnectionClientStateResponse.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.identifiedClientState != null && Object.hasOwnProperty.call(m, "identifiedClientState"))
              $root.ibc.core.client.v1.IdentifiedClientState.encode(
                m.identifiedClientState,
                w.uint32(10).fork(),
              ).ldelim();
            if (m.proof != null && Object.hasOwnProperty.call(m, "proof")) w.uint32(18).bytes(m.proof);
            if (m.proofPath != null && Object.hasOwnProperty.call(m, "proofPath"))
              w.uint32(26).string(m.proofPath);
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(34).fork()).ldelim();
            return w;
          };
          QueryConnectionClientStateResponse.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.connection.v1.QueryConnectionClientStateResponse();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.identifiedClientState = $root.ibc.core.client.v1.IdentifiedClientState.decode(
                    r,
                    r.uint32(),
                  );
                  break;
                case 2:
                  m.proof = r.bytes();
                  break;
                case 3:
                  m.proofPath = r.string();
                  break;
                case 4:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryConnectionClientStateResponse;
        })();
        v1.QueryConnectionConsensusStateRequest = (function () {
          function QueryConnectionConsensusStateRequest(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryConnectionConsensusStateRequest.prototype.connectionId = "";
          QueryConnectionConsensusStateRequest.prototype.versionNumber = $util.Long
            ? $util.Long.fromBits(0, 0, true)
            : 0;
          QueryConnectionConsensusStateRequest.prototype.versionHeight = $util.Long
            ? $util.Long.fromBits(0, 0, true)
            : 0;
          QueryConnectionConsensusStateRequest.create = function create(properties) {
            return new QueryConnectionConsensusStateRequest(properties);
          };
          QueryConnectionConsensusStateRequest.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.connectionId != null && Object.hasOwnProperty.call(m, "connectionId"))
              w.uint32(10).string(m.connectionId);
            if (m.versionNumber != null && Object.hasOwnProperty.call(m, "versionNumber"))
              w.uint32(16).uint64(m.versionNumber);
            if (m.versionHeight != null && Object.hasOwnProperty.call(m, "versionHeight"))
              w.uint32(24).uint64(m.versionHeight);
            return w;
          };
          QueryConnectionConsensusStateRequest.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.connection.v1.QueryConnectionConsensusStateRequest();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.connectionId = r.string();
                  break;
                case 2:
                  m.versionNumber = r.uint64();
                  break;
                case 3:
                  m.versionHeight = r.uint64();
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryConnectionConsensusStateRequest;
        })();
        v1.QueryConnectionConsensusStateResponse = (function () {
          function QueryConnectionConsensusStateResponse(p) {
            if (p)
              for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
                if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
          }
          QueryConnectionConsensusStateResponse.prototype.consensusState = null;
          QueryConnectionConsensusStateResponse.prototype.clientId = "";
          QueryConnectionConsensusStateResponse.prototype.proof = $util.newBuffer([]);
          QueryConnectionConsensusStateResponse.prototype.proofPath = "";
          QueryConnectionConsensusStateResponse.prototype.proofHeight = null;
          QueryConnectionConsensusStateResponse.create = function create(properties) {
            return new QueryConnectionConsensusStateResponse(properties);
          };
          QueryConnectionConsensusStateResponse.encode = function encode(m, w) {
            if (!w) w = $Writer.create();
            if (m.consensusState != null && Object.hasOwnProperty.call(m, "consensusState"))
              $root.google.protobuf.Any.encode(m.consensusState, w.uint32(10).fork()).ldelim();
            if (m.clientId != null && Object.hasOwnProperty.call(m, "clientId"))
              w.uint32(18).string(m.clientId);
            if (m.proof != null && Object.hasOwnProperty.call(m, "proof")) w.uint32(26).bytes(m.proof);
            if (m.proofPath != null && Object.hasOwnProperty.call(m, "proofPath"))
              w.uint32(34).string(m.proofPath);
            if (m.proofHeight != null && Object.hasOwnProperty.call(m, "proofHeight"))
              $root.ibc.core.client.v1.Height.encode(m.proofHeight, w.uint32(42).fork()).ldelim();
            return w;
          };
          QueryConnectionConsensusStateResponse.decode = function decode(r, l) {
            if (!(r instanceof $Reader)) r = $Reader.create(r);
            var c = l === undefined ? r.len : r.pos + l,
              m = new $root.ibc.core.connection.v1.QueryConnectionConsensusStateResponse();
            while (r.pos < c) {
              var t = r.uint32();
              switch (t >>> 3) {
                case 1:
                  m.consensusState = $root.google.protobuf.Any.decode(r, r.uint32());
                  break;
                case 2:
                  m.clientId = r.string();
                  break;
                case 3:
                  m.proof = r.bytes();
                  break;
                case 4:
                  m.proofPath = r.string();
                  break;
                case 5:
                  m.proofHeight = $root.ibc.core.client.v1.Height.decode(r, r.uint32());
                  break;
                default:
                  r.skipType(t & 7);
                  break;
              }
            }
            return m;
          };
          return QueryConnectionConsensusStateResponse;
        })();
        return v1;
      })();
      return connection;
    })();
    return core;
  })();
  return ibc;
})();
exports.tendermint = $root.tendermint = (() => {
  const tendermint = {};
  tendermint.crypto = (function () {
    const crypto = {};
    crypto.Proof = (function () {
      function Proof(p) {
        this.aunts = [];
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      Proof.prototype.total = $util.Long ? $util.Long.fromBits(0, 0, false) : 0;
      Proof.prototype.index = $util.Long ? $util.Long.fromBits(0, 0, false) : 0;
      Proof.prototype.leafHash = $util.newBuffer([]);
      Proof.prototype.aunts = $util.emptyArray;
      Proof.create = function create(properties) {
        return new Proof(properties);
      };
      Proof.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.total != null && Object.hasOwnProperty.call(m, "total")) w.uint32(8).int64(m.total);
        if (m.index != null && Object.hasOwnProperty.call(m, "index")) w.uint32(16).int64(m.index);
        if (m.leafHash != null && Object.hasOwnProperty.call(m, "leafHash")) w.uint32(26).bytes(m.leafHash);
        if (m.aunts != null && m.aunts.length) {
          for (var i = 0; i < m.aunts.length; ++i) w.uint32(34).bytes(m.aunts[i]);
        }
        return w;
      };
      Proof.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.tendermint.crypto.Proof();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              m.total = r.int64();
              break;
            case 2:
              m.index = r.int64();
              break;
            case 3:
              m.leafHash = r.bytes();
              break;
            case 4:
              if (!(m.aunts && m.aunts.length)) m.aunts = [];
              m.aunts.push(r.bytes());
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return Proof;
    })();
    crypto.ValueOp = (function () {
      function ValueOp(p) {
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      ValueOp.prototype.key = $util.newBuffer([]);
      ValueOp.prototype.proof = null;
      ValueOp.create = function create(properties) {
        return new ValueOp(properties);
      };
      ValueOp.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.key != null && Object.hasOwnProperty.call(m, "key")) w.uint32(10).bytes(m.key);
        if (m.proof != null && Object.hasOwnProperty.call(m, "proof"))
          $root.tendermint.crypto.Proof.encode(m.proof, w.uint32(18).fork()).ldelim();
        return w;
      };
      ValueOp.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.tendermint.crypto.ValueOp();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              m.key = r.bytes();
              break;
            case 2:
              m.proof = $root.tendermint.crypto.Proof.decode(r, r.uint32());
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return ValueOp;
    })();
    crypto.DominoOp = (function () {
      function DominoOp(p) {
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      DominoOp.prototype.key = "";
      DominoOp.prototype.input = "";
      DominoOp.prototype.output = "";
      DominoOp.create = function create(properties) {
        return new DominoOp(properties);
      };
      DominoOp.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.key != null && Object.hasOwnProperty.call(m, "key")) w.uint32(10).string(m.key);
        if (m.input != null && Object.hasOwnProperty.call(m, "input")) w.uint32(18).string(m.input);
        if (m.output != null && Object.hasOwnProperty.call(m, "output")) w.uint32(26).string(m.output);
        return w;
      };
      DominoOp.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.tendermint.crypto.DominoOp();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              m.key = r.string();
              break;
            case 2:
              m.input = r.string();
              break;
            case 3:
              m.output = r.string();
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return DominoOp;
    })();
    crypto.ProofOp = (function () {
      function ProofOp(p) {
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      ProofOp.prototype.type = "";
      ProofOp.prototype.key = $util.newBuffer([]);
      ProofOp.prototype.data = $util.newBuffer([]);
      ProofOp.create = function create(properties) {
        return new ProofOp(properties);
      };
      ProofOp.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.type != null && Object.hasOwnProperty.call(m, "type")) w.uint32(10).string(m.type);
        if (m.key != null && Object.hasOwnProperty.call(m, "key")) w.uint32(18).bytes(m.key);
        if (m.data != null && Object.hasOwnProperty.call(m, "data")) w.uint32(26).bytes(m.data);
        return w;
      };
      ProofOp.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.tendermint.crypto.ProofOp();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              m.type = r.string();
              break;
            case 2:
              m.key = r.bytes();
              break;
            case 3:
              m.data = r.bytes();
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return ProofOp;
    })();
    crypto.ProofOps = (function () {
      function ProofOps(p) {
        this.ops = [];
        if (p)
          for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
            if (p[ks[i]] != null) this[ks[i]] = p[ks[i]];
      }
      ProofOps.prototype.ops = $util.emptyArray;
      ProofOps.create = function create(properties) {
        return new ProofOps(properties);
      };
      ProofOps.encode = function encode(m, w) {
        if (!w) w = $Writer.create();
        if (m.ops != null && m.ops.length) {
          for (var i = 0; i < m.ops.length; ++i)
            $root.tendermint.crypto.ProofOp.encode(m.ops[i], w.uint32(10).fork()).ldelim();
        }
        return w;
      };
      ProofOps.decode = function decode(r, l) {
        if (!(r instanceof $Reader)) r = $Reader.create(r);
        var c = l === undefined ? r.len : r.pos + l,
          m = new $root.tendermint.crypto.ProofOps();
        while (r.pos < c) {
          var t = r.uint32();
          switch (t >>> 3) {
            case 1:
              if (!(m.ops && m.ops.length)) m.ops = [];
              m.ops.push($root.tendermint.crypto.ProofOp.decode(r, r.uint32()));
              break;
            default:
              r.skipType(t & 7);
              break;
          }
        }
        return m;
      };
      return ProofOps;
    })();
    return crypto;
  })();
  return tendermint;
})();
module.exports = $root;
