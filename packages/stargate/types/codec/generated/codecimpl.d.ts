import * as $protobuf from "protobufjs";
/** Namespace cosmos. */
export namespace cosmos {
  /** Namespace auth. */
  namespace auth {
    /** Namespace v1beta1. */
    namespace v1beta1 {
      /** Properties of a BaseAccount. */
      interface IBaseAccount {
        /** BaseAccount address */
        address?: string | null;

        /** BaseAccount pubKey */
        pubKey?: google.protobuf.IAny | null;

        /** BaseAccount accountNumber */
        accountNumber?: Long | null;

        /** BaseAccount sequence */
        sequence?: Long | null;
      }

      /** Represents a BaseAccount. */
      class BaseAccount implements IBaseAccount {
        /**
         * Constructs a new BaseAccount.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.auth.v1beta1.IBaseAccount);

        /** BaseAccount address. */
        public address: string;

        /** BaseAccount pubKey. */
        public pubKey?: google.protobuf.IAny | null;

        /** BaseAccount accountNumber. */
        public accountNumber: Long;

        /** BaseAccount sequence. */
        public sequence: Long;

        /**
         * Creates a new BaseAccount instance using the specified properties.
         * @param [properties] Properties to set
         * @returns BaseAccount instance
         */
        public static create(properties?: cosmos.auth.v1beta1.IBaseAccount): cosmos.auth.v1beta1.BaseAccount;

        /**
         * Encodes the specified BaseAccount message. Does not implicitly {@link cosmos.auth.v1beta1.BaseAccount.verify|verify} messages.
         * @param m BaseAccount message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(m: cosmos.auth.v1beta1.IBaseAccount, w?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a BaseAccount message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns BaseAccount
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(r: $protobuf.Reader | Uint8Array, l?: number): cosmos.auth.v1beta1.BaseAccount;
      }

      /** Properties of a ModuleAccount. */
      interface IModuleAccount {
        /** ModuleAccount baseAccount */
        baseAccount?: cosmos.auth.v1beta1.IBaseAccount | null;

        /** ModuleAccount name */
        name?: string | null;

        /** ModuleAccount permissions */
        permissions?: string[] | null;
      }

      /** Represents a ModuleAccount. */
      class ModuleAccount implements IModuleAccount {
        /**
         * Constructs a new ModuleAccount.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.auth.v1beta1.IModuleAccount);

        /** ModuleAccount baseAccount. */
        public baseAccount?: cosmos.auth.v1beta1.IBaseAccount | null;

        /** ModuleAccount name. */
        public name: string;

        /** ModuleAccount permissions. */
        public permissions: string[];

        /**
         * Creates a new ModuleAccount instance using the specified properties.
         * @param [properties] Properties to set
         * @returns ModuleAccount instance
         */
        public static create(
          properties?: cosmos.auth.v1beta1.IModuleAccount,
        ): cosmos.auth.v1beta1.ModuleAccount;

        /**
         * Encodes the specified ModuleAccount message. Does not implicitly {@link cosmos.auth.v1beta1.ModuleAccount.verify|verify} messages.
         * @param m ModuleAccount message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(m: cosmos.auth.v1beta1.IModuleAccount, w?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a ModuleAccount message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns ModuleAccount
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(r: $protobuf.Reader | Uint8Array, l?: number): cosmos.auth.v1beta1.ModuleAccount;
      }

      /** Properties of a Params. */
      interface IParams {
        /** Params maxMemoCharacters */
        maxMemoCharacters?: Long | null;

        /** Params txSigLimit */
        txSigLimit?: Long | null;

        /** Params txSizeCostPerByte */
        txSizeCostPerByte?: Long | null;

        /** Params sigVerifyCostEd25519 */
        sigVerifyCostEd25519?: Long | null;

        /** Params sigVerifyCostSecp256k1 */
        sigVerifyCostSecp256k1?: Long | null;
      }

      /** Represents a Params. */
      class Params implements IParams {
        /**
         * Constructs a new Params.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.auth.v1beta1.IParams);

        /** Params maxMemoCharacters. */
        public maxMemoCharacters: Long;

        /** Params txSigLimit. */
        public txSigLimit: Long;

        /** Params txSizeCostPerByte. */
        public txSizeCostPerByte: Long;

        /** Params sigVerifyCostEd25519. */
        public sigVerifyCostEd25519: Long;

        /** Params sigVerifyCostSecp256k1. */
        public sigVerifyCostSecp256k1: Long;

        /**
         * Creates a new Params instance using the specified properties.
         * @param [properties] Properties to set
         * @returns Params instance
         */
        public static create(properties?: cosmos.auth.v1beta1.IParams): cosmos.auth.v1beta1.Params;

        /**
         * Encodes the specified Params message. Does not implicitly {@link cosmos.auth.v1beta1.Params.verify|verify} messages.
         * @param m Params message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(m: cosmos.auth.v1beta1.IParams, w?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a Params message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns Params
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(r: $protobuf.Reader | Uint8Array, l?: number): cosmos.auth.v1beta1.Params;
      }

      /** Represents a Query */
      class Query extends $protobuf.rpc.Service {
        /**
         * Constructs a new Query service.
         * @param rpcImpl RPC implementation
         * @param [requestDelimited=false] Whether requests are length-delimited
         * @param [responseDelimited=false] Whether responses are length-delimited
         */
        constructor(rpcImpl: $protobuf.RPCImpl, requestDelimited?: boolean, responseDelimited?: boolean);

        /**
         * Creates new Query service using the specified rpc implementation.
         * @param rpcImpl RPC implementation
         * @param [requestDelimited=false] Whether requests are length-delimited
         * @param [responseDelimited=false] Whether responses are length-delimited
         * @returns RPC service. Useful where requests and/or responses are streamed.
         */
        public static create(
          rpcImpl: $protobuf.RPCImpl,
          requestDelimited?: boolean,
          responseDelimited?: boolean,
        ): Query;

        /**
         * Calls Account.
         * @param request QueryAccountRequest message or plain object
         * @param callback Node-style callback called with the error, if any, and QueryAccountResponse
         */
        public account(
          request: cosmos.auth.v1beta1.IQueryAccountRequest,
          callback: cosmos.auth.v1beta1.Query.AccountCallback,
        ): void;

        /**
         * Calls Account.
         * @param request QueryAccountRequest message or plain object
         * @returns Promise
         */
        public account(
          request: cosmos.auth.v1beta1.IQueryAccountRequest,
        ): Promise<cosmos.auth.v1beta1.QueryAccountResponse>;

        /**
         * Calls Params.
         * @param request QueryParamsRequest message or plain object
         * @param callback Node-style callback called with the error, if any, and QueryParamsResponse
         */
        public params(
          request: cosmos.auth.v1beta1.IQueryParamsRequest,
          callback: cosmos.auth.v1beta1.Query.ParamsCallback,
        ): void;

        /**
         * Calls Params.
         * @param request QueryParamsRequest message or plain object
         * @returns Promise
         */
        public params(
          request: cosmos.auth.v1beta1.IQueryParamsRequest,
        ): Promise<cosmos.auth.v1beta1.QueryParamsResponse>;
      }

      namespace Query {
        /**
         * Callback as used by {@link cosmos.auth.v1beta1.Query#account}.
         * @param error Error, if any
         * @param [response] QueryAccountResponse
         */
        type AccountCallback = (
          error: Error | null,
          response?: cosmos.auth.v1beta1.QueryAccountResponse,
        ) => void;

        /**
         * Callback as used by {@link cosmos.auth.v1beta1.Query#params}.
         * @param error Error, if any
         * @param [response] QueryParamsResponse
         */
        type ParamsCallback = (
          error: Error | null,
          response?: cosmos.auth.v1beta1.QueryParamsResponse,
        ) => void;
      }

      /** Properties of a QueryAccountRequest. */
      interface IQueryAccountRequest {
        /** QueryAccountRequest address */
        address?: string | null;
      }

      /** Represents a QueryAccountRequest. */
      class QueryAccountRequest implements IQueryAccountRequest {
        /**
         * Constructs a new QueryAccountRequest.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.auth.v1beta1.IQueryAccountRequest);

        /** QueryAccountRequest address. */
        public address: string;

        /**
         * Creates a new QueryAccountRequest instance using the specified properties.
         * @param [properties] Properties to set
         * @returns QueryAccountRequest instance
         */
        public static create(
          properties?: cosmos.auth.v1beta1.IQueryAccountRequest,
        ): cosmos.auth.v1beta1.QueryAccountRequest;

        /**
         * Encodes the specified QueryAccountRequest message. Does not implicitly {@link cosmos.auth.v1beta1.QueryAccountRequest.verify|verify} messages.
         * @param m QueryAccountRequest message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(
          m: cosmos.auth.v1beta1.IQueryAccountRequest,
          w?: $protobuf.Writer,
        ): $protobuf.Writer;

        /**
         * Decodes a QueryAccountRequest message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns QueryAccountRequest
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(
          r: $protobuf.Reader | Uint8Array,
          l?: number,
        ): cosmos.auth.v1beta1.QueryAccountRequest;
      }

      /** Properties of a QueryAccountResponse. */
      interface IQueryAccountResponse {
        /** QueryAccountResponse account */
        account?: google.protobuf.IAny | null;
      }

      /** Represents a QueryAccountResponse. */
      class QueryAccountResponse implements IQueryAccountResponse {
        /**
         * Constructs a new QueryAccountResponse.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.auth.v1beta1.IQueryAccountResponse);

        /** QueryAccountResponse account. */
        public account?: google.protobuf.IAny | null;

        /**
         * Creates a new QueryAccountResponse instance using the specified properties.
         * @param [properties] Properties to set
         * @returns QueryAccountResponse instance
         */
        public static create(
          properties?: cosmos.auth.v1beta1.IQueryAccountResponse,
        ): cosmos.auth.v1beta1.QueryAccountResponse;

        /**
         * Encodes the specified QueryAccountResponse message. Does not implicitly {@link cosmos.auth.v1beta1.QueryAccountResponse.verify|verify} messages.
         * @param m QueryAccountResponse message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(
          m: cosmos.auth.v1beta1.IQueryAccountResponse,
          w?: $protobuf.Writer,
        ): $protobuf.Writer;

        /**
         * Decodes a QueryAccountResponse message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns QueryAccountResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(
          r: $protobuf.Reader | Uint8Array,
          l?: number,
        ): cosmos.auth.v1beta1.QueryAccountResponse;
      }

      /** Properties of a QueryParamsRequest. */
      interface IQueryParamsRequest {}

      /** Represents a QueryParamsRequest. */
      class QueryParamsRequest implements IQueryParamsRequest {
        /**
         * Constructs a new QueryParamsRequest.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.auth.v1beta1.IQueryParamsRequest);

        /**
         * Creates a new QueryParamsRequest instance using the specified properties.
         * @param [properties] Properties to set
         * @returns QueryParamsRequest instance
         */
        public static create(
          properties?: cosmos.auth.v1beta1.IQueryParamsRequest,
        ): cosmos.auth.v1beta1.QueryParamsRequest;

        /**
         * Encodes the specified QueryParamsRequest message. Does not implicitly {@link cosmos.auth.v1beta1.QueryParamsRequest.verify|verify} messages.
         * @param m QueryParamsRequest message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(
          m: cosmos.auth.v1beta1.IQueryParamsRequest,
          w?: $protobuf.Writer,
        ): $protobuf.Writer;

        /**
         * Decodes a QueryParamsRequest message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns QueryParamsRequest
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(
          r: $protobuf.Reader | Uint8Array,
          l?: number,
        ): cosmos.auth.v1beta1.QueryParamsRequest;
      }

      /** Properties of a QueryParamsResponse. */
      interface IQueryParamsResponse {
        /** QueryParamsResponse params */
        params?: cosmos.auth.v1beta1.IParams | null;
      }

      /** Represents a QueryParamsResponse. */
      class QueryParamsResponse implements IQueryParamsResponse {
        /**
         * Constructs a new QueryParamsResponse.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.auth.v1beta1.IQueryParamsResponse);

        /** QueryParamsResponse params. */
        public params?: cosmos.auth.v1beta1.IParams | null;

        /**
         * Creates a new QueryParamsResponse instance using the specified properties.
         * @param [properties] Properties to set
         * @returns QueryParamsResponse instance
         */
        public static create(
          properties?: cosmos.auth.v1beta1.IQueryParamsResponse,
        ): cosmos.auth.v1beta1.QueryParamsResponse;

        /**
         * Encodes the specified QueryParamsResponse message. Does not implicitly {@link cosmos.auth.v1beta1.QueryParamsResponse.verify|verify} messages.
         * @param m QueryParamsResponse message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(
          m: cosmos.auth.v1beta1.IQueryParamsResponse,
          w?: $protobuf.Writer,
        ): $protobuf.Writer;

        /**
         * Decodes a QueryParamsResponse message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns QueryParamsResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(
          r: $protobuf.Reader | Uint8Array,
          l?: number,
        ): cosmos.auth.v1beta1.QueryParamsResponse;
      }
    }
  }

  /** Namespace bank. */
  namespace bank {
    /** Namespace v1beta1. */
    namespace v1beta1 {
      /** Represents a Query */
      class Query extends $protobuf.rpc.Service {
        /**
         * Constructs a new Query service.
         * @param rpcImpl RPC implementation
         * @param [requestDelimited=false] Whether requests are length-delimited
         * @param [responseDelimited=false] Whether responses are length-delimited
         */
        constructor(rpcImpl: $protobuf.RPCImpl, requestDelimited?: boolean, responseDelimited?: boolean);

        /**
         * Creates new Query service using the specified rpc implementation.
         * @param rpcImpl RPC implementation
         * @param [requestDelimited=false] Whether requests are length-delimited
         * @param [responseDelimited=false] Whether responses are length-delimited
         * @returns RPC service. Useful where requests and/or responses are streamed.
         */
        public static create(
          rpcImpl: $protobuf.RPCImpl,
          requestDelimited?: boolean,
          responseDelimited?: boolean,
        ): Query;

        /**
         * Calls Balance.
         * @param request QueryBalanceRequest message or plain object
         * @param callback Node-style callback called with the error, if any, and QueryBalanceResponse
         */
        public balance(
          request: cosmos.bank.v1beta1.IQueryBalanceRequest,
          callback: cosmos.bank.v1beta1.Query.BalanceCallback,
        ): void;

        /**
         * Calls Balance.
         * @param request QueryBalanceRequest message or plain object
         * @returns Promise
         */
        public balance(
          request: cosmos.bank.v1beta1.IQueryBalanceRequest,
        ): Promise<cosmos.bank.v1beta1.QueryBalanceResponse>;

        /**
         * Calls AllBalances.
         * @param request QueryAllBalancesRequest message or plain object
         * @param callback Node-style callback called with the error, if any, and QueryAllBalancesResponse
         */
        public allBalances(
          request: cosmos.bank.v1beta1.IQueryAllBalancesRequest,
          callback: cosmos.bank.v1beta1.Query.AllBalancesCallback,
        ): void;

        /**
         * Calls AllBalances.
         * @param request QueryAllBalancesRequest message or plain object
         * @returns Promise
         */
        public allBalances(
          request: cosmos.bank.v1beta1.IQueryAllBalancesRequest,
        ): Promise<cosmos.bank.v1beta1.QueryAllBalancesResponse>;

        /**
         * Calls TotalSupply.
         * @param request QueryTotalSupplyRequest message or plain object
         * @param callback Node-style callback called with the error, if any, and QueryTotalSupplyResponse
         */
        public totalSupply(
          request: cosmos.bank.v1beta1.IQueryTotalSupplyRequest,
          callback: cosmos.bank.v1beta1.Query.TotalSupplyCallback,
        ): void;

        /**
         * Calls TotalSupply.
         * @param request QueryTotalSupplyRequest message or plain object
         * @returns Promise
         */
        public totalSupply(
          request: cosmos.bank.v1beta1.IQueryTotalSupplyRequest,
        ): Promise<cosmos.bank.v1beta1.QueryTotalSupplyResponse>;

        /**
         * Calls SupplyOf.
         * @param request QuerySupplyOfRequest message or plain object
         * @param callback Node-style callback called with the error, if any, and QuerySupplyOfResponse
         */
        public supplyOf(
          request: cosmos.bank.v1beta1.IQuerySupplyOfRequest,
          callback: cosmos.bank.v1beta1.Query.SupplyOfCallback,
        ): void;

        /**
         * Calls SupplyOf.
         * @param request QuerySupplyOfRequest message or plain object
         * @returns Promise
         */
        public supplyOf(
          request: cosmos.bank.v1beta1.IQuerySupplyOfRequest,
        ): Promise<cosmos.bank.v1beta1.QuerySupplyOfResponse>;

        /**
         * Calls Params.
         * @param request QueryParamsRequest message or plain object
         * @param callback Node-style callback called with the error, if any, and QueryParamsResponse
         */
        public params(
          request: cosmos.bank.v1beta1.IQueryParamsRequest,
          callback: cosmos.bank.v1beta1.Query.ParamsCallback,
        ): void;

        /**
         * Calls Params.
         * @param request QueryParamsRequest message or plain object
         * @returns Promise
         */
        public params(
          request: cosmos.bank.v1beta1.IQueryParamsRequest,
        ): Promise<cosmos.bank.v1beta1.QueryParamsResponse>;
      }

      namespace Query {
        /**
         * Callback as used by {@link cosmos.bank.v1beta1.Query#balance}.
         * @param error Error, if any
         * @param [response] QueryBalanceResponse
         */
        type BalanceCallback = (
          error: Error | null,
          response?: cosmos.bank.v1beta1.QueryBalanceResponse,
        ) => void;

        /**
         * Callback as used by {@link cosmos.bank.v1beta1.Query#allBalances}.
         * @param error Error, if any
         * @param [response] QueryAllBalancesResponse
         */
        type AllBalancesCallback = (
          error: Error | null,
          response?: cosmos.bank.v1beta1.QueryAllBalancesResponse,
        ) => void;

        /**
         * Callback as used by {@link cosmos.bank.v1beta1.Query#totalSupply}.
         * @param error Error, if any
         * @param [response] QueryTotalSupplyResponse
         */
        type TotalSupplyCallback = (
          error: Error | null,
          response?: cosmos.bank.v1beta1.QueryTotalSupplyResponse,
        ) => void;

        /**
         * Callback as used by {@link cosmos.bank.v1beta1.Query#supplyOf}.
         * @param error Error, if any
         * @param [response] QuerySupplyOfResponse
         */
        type SupplyOfCallback = (
          error: Error | null,
          response?: cosmos.bank.v1beta1.QuerySupplyOfResponse,
        ) => void;

        /**
         * Callback as used by {@link cosmos.bank.v1beta1.Query#params}.
         * @param error Error, if any
         * @param [response] QueryParamsResponse
         */
        type ParamsCallback = (
          error: Error | null,
          response?: cosmos.bank.v1beta1.QueryParamsResponse,
        ) => void;
      }

      /** Properties of a QueryBalanceRequest. */
      interface IQueryBalanceRequest {
        /** QueryBalanceRequest address */
        address?: string | null;

        /** QueryBalanceRequest denom */
        denom?: string | null;
      }

      /** Represents a QueryBalanceRequest. */
      class QueryBalanceRequest implements IQueryBalanceRequest {
        /**
         * Constructs a new QueryBalanceRequest.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.bank.v1beta1.IQueryBalanceRequest);

        /** QueryBalanceRequest address. */
        public address: string;

        /** QueryBalanceRequest denom. */
        public denom: string;

        /**
         * Creates a new QueryBalanceRequest instance using the specified properties.
         * @param [properties] Properties to set
         * @returns QueryBalanceRequest instance
         */
        public static create(
          properties?: cosmos.bank.v1beta1.IQueryBalanceRequest,
        ): cosmos.bank.v1beta1.QueryBalanceRequest;

        /**
         * Encodes the specified QueryBalanceRequest message. Does not implicitly {@link cosmos.bank.v1beta1.QueryBalanceRequest.verify|verify} messages.
         * @param m QueryBalanceRequest message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(
          m: cosmos.bank.v1beta1.IQueryBalanceRequest,
          w?: $protobuf.Writer,
        ): $protobuf.Writer;

        /**
         * Decodes a QueryBalanceRequest message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns QueryBalanceRequest
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(
          r: $protobuf.Reader | Uint8Array,
          l?: number,
        ): cosmos.bank.v1beta1.QueryBalanceRequest;
      }

      /** Properties of a QueryBalanceResponse. */
      interface IQueryBalanceResponse {
        /** QueryBalanceResponse balance */
        balance?: cosmos.base.v1beta1.ICoin | null;
      }

      /** Represents a QueryBalanceResponse. */
      class QueryBalanceResponse implements IQueryBalanceResponse {
        /**
         * Constructs a new QueryBalanceResponse.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.bank.v1beta1.IQueryBalanceResponse);

        /** QueryBalanceResponse balance. */
        public balance?: cosmos.base.v1beta1.ICoin | null;

        /**
         * Creates a new QueryBalanceResponse instance using the specified properties.
         * @param [properties] Properties to set
         * @returns QueryBalanceResponse instance
         */
        public static create(
          properties?: cosmos.bank.v1beta1.IQueryBalanceResponse,
        ): cosmos.bank.v1beta1.QueryBalanceResponse;

        /**
         * Encodes the specified QueryBalanceResponse message. Does not implicitly {@link cosmos.bank.v1beta1.QueryBalanceResponse.verify|verify} messages.
         * @param m QueryBalanceResponse message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(
          m: cosmos.bank.v1beta1.IQueryBalanceResponse,
          w?: $protobuf.Writer,
        ): $protobuf.Writer;

        /**
         * Decodes a QueryBalanceResponse message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns QueryBalanceResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(
          r: $protobuf.Reader | Uint8Array,
          l?: number,
        ): cosmos.bank.v1beta1.QueryBalanceResponse;
      }

      /** Properties of a QueryAllBalancesRequest. */
      interface IQueryAllBalancesRequest {
        /** QueryAllBalancesRequest address */
        address?: string | null;

        /** QueryAllBalancesRequest pagination */
        pagination?: cosmos.base.query.v1beta1.IPageRequest | null;
      }

      /** Represents a QueryAllBalancesRequest. */
      class QueryAllBalancesRequest implements IQueryAllBalancesRequest {
        /**
         * Constructs a new QueryAllBalancesRequest.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.bank.v1beta1.IQueryAllBalancesRequest);

        /** QueryAllBalancesRequest address. */
        public address: string;

        /** QueryAllBalancesRequest pagination. */
        public pagination?: cosmos.base.query.v1beta1.IPageRequest | null;

        /**
         * Creates a new QueryAllBalancesRequest instance using the specified properties.
         * @param [properties] Properties to set
         * @returns QueryAllBalancesRequest instance
         */
        public static create(
          properties?: cosmos.bank.v1beta1.IQueryAllBalancesRequest,
        ): cosmos.bank.v1beta1.QueryAllBalancesRequest;

        /**
         * Encodes the specified QueryAllBalancesRequest message. Does not implicitly {@link cosmos.bank.v1beta1.QueryAllBalancesRequest.verify|verify} messages.
         * @param m QueryAllBalancesRequest message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(
          m: cosmos.bank.v1beta1.IQueryAllBalancesRequest,
          w?: $protobuf.Writer,
        ): $protobuf.Writer;

        /**
         * Decodes a QueryAllBalancesRequest message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns QueryAllBalancesRequest
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(
          r: $protobuf.Reader | Uint8Array,
          l?: number,
        ): cosmos.bank.v1beta1.QueryAllBalancesRequest;
      }

      /** Properties of a QueryAllBalancesResponse. */
      interface IQueryAllBalancesResponse {
        /** QueryAllBalancesResponse balances */
        balances?: cosmos.base.v1beta1.ICoin[] | null;

        /** QueryAllBalancesResponse pagination */
        pagination?: cosmos.base.query.v1beta1.IPageResponse | null;
      }

      /** Represents a QueryAllBalancesResponse. */
      class QueryAllBalancesResponse implements IQueryAllBalancesResponse {
        /**
         * Constructs a new QueryAllBalancesResponse.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.bank.v1beta1.IQueryAllBalancesResponse);

        /** QueryAllBalancesResponse balances. */
        public balances: cosmos.base.v1beta1.ICoin[];

        /** QueryAllBalancesResponse pagination. */
        public pagination?: cosmos.base.query.v1beta1.IPageResponse | null;

        /**
         * Creates a new QueryAllBalancesResponse instance using the specified properties.
         * @param [properties] Properties to set
         * @returns QueryAllBalancesResponse instance
         */
        public static create(
          properties?: cosmos.bank.v1beta1.IQueryAllBalancesResponse,
        ): cosmos.bank.v1beta1.QueryAllBalancesResponse;

        /**
         * Encodes the specified QueryAllBalancesResponse message. Does not implicitly {@link cosmos.bank.v1beta1.QueryAllBalancesResponse.verify|verify} messages.
         * @param m QueryAllBalancesResponse message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(
          m: cosmos.bank.v1beta1.IQueryAllBalancesResponse,
          w?: $protobuf.Writer,
        ): $protobuf.Writer;

        /**
         * Decodes a QueryAllBalancesResponse message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns QueryAllBalancesResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(
          r: $protobuf.Reader | Uint8Array,
          l?: number,
        ): cosmos.bank.v1beta1.QueryAllBalancesResponse;
      }

      /** Properties of a QueryTotalSupplyRequest. */
      interface IQueryTotalSupplyRequest {}

      /** Represents a QueryTotalSupplyRequest. */
      class QueryTotalSupplyRequest implements IQueryTotalSupplyRequest {
        /**
         * Constructs a new QueryTotalSupplyRequest.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.bank.v1beta1.IQueryTotalSupplyRequest);

        /**
         * Creates a new QueryTotalSupplyRequest instance using the specified properties.
         * @param [properties] Properties to set
         * @returns QueryTotalSupplyRequest instance
         */
        public static create(
          properties?: cosmos.bank.v1beta1.IQueryTotalSupplyRequest,
        ): cosmos.bank.v1beta1.QueryTotalSupplyRequest;

        /**
         * Encodes the specified QueryTotalSupplyRequest message. Does not implicitly {@link cosmos.bank.v1beta1.QueryTotalSupplyRequest.verify|verify} messages.
         * @param m QueryTotalSupplyRequest message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(
          m: cosmos.bank.v1beta1.IQueryTotalSupplyRequest,
          w?: $protobuf.Writer,
        ): $protobuf.Writer;

        /**
         * Decodes a QueryTotalSupplyRequest message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns QueryTotalSupplyRequest
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(
          r: $protobuf.Reader | Uint8Array,
          l?: number,
        ): cosmos.bank.v1beta1.QueryTotalSupplyRequest;
      }

      /** Properties of a QueryTotalSupplyResponse. */
      interface IQueryTotalSupplyResponse {
        /** QueryTotalSupplyResponse supply */
        supply?: cosmos.base.v1beta1.ICoin[] | null;
      }

      /** Represents a QueryTotalSupplyResponse. */
      class QueryTotalSupplyResponse implements IQueryTotalSupplyResponse {
        /**
         * Constructs a new QueryTotalSupplyResponse.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.bank.v1beta1.IQueryTotalSupplyResponse);

        /** QueryTotalSupplyResponse supply. */
        public supply: cosmos.base.v1beta1.ICoin[];

        /**
         * Creates a new QueryTotalSupplyResponse instance using the specified properties.
         * @param [properties] Properties to set
         * @returns QueryTotalSupplyResponse instance
         */
        public static create(
          properties?: cosmos.bank.v1beta1.IQueryTotalSupplyResponse,
        ): cosmos.bank.v1beta1.QueryTotalSupplyResponse;

        /**
         * Encodes the specified QueryTotalSupplyResponse message. Does not implicitly {@link cosmos.bank.v1beta1.QueryTotalSupplyResponse.verify|verify} messages.
         * @param m QueryTotalSupplyResponse message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(
          m: cosmos.bank.v1beta1.IQueryTotalSupplyResponse,
          w?: $protobuf.Writer,
        ): $protobuf.Writer;

        /**
         * Decodes a QueryTotalSupplyResponse message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns QueryTotalSupplyResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(
          r: $protobuf.Reader | Uint8Array,
          l?: number,
        ): cosmos.bank.v1beta1.QueryTotalSupplyResponse;
      }

      /** Properties of a QuerySupplyOfRequest. */
      interface IQuerySupplyOfRequest {
        /** QuerySupplyOfRequest denom */
        denom?: string | null;
      }

      /** Represents a QuerySupplyOfRequest. */
      class QuerySupplyOfRequest implements IQuerySupplyOfRequest {
        /**
         * Constructs a new QuerySupplyOfRequest.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.bank.v1beta1.IQuerySupplyOfRequest);

        /** QuerySupplyOfRequest denom. */
        public denom: string;

        /**
         * Creates a new QuerySupplyOfRequest instance using the specified properties.
         * @param [properties] Properties to set
         * @returns QuerySupplyOfRequest instance
         */
        public static create(
          properties?: cosmos.bank.v1beta1.IQuerySupplyOfRequest,
        ): cosmos.bank.v1beta1.QuerySupplyOfRequest;

        /**
         * Encodes the specified QuerySupplyOfRequest message. Does not implicitly {@link cosmos.bank.v1beta1.QuerySupplyOfRequest.verify|verify} messages.
         * @param m QuerySupplyOfRequest message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(
          m: cosmos.bank.v1beta1.IQuerySupplyOfRequest,
          w?: $protobuf.Writer,
        ): $protobuf.Writer;

        /**
         * Decodes a QuerySupplyOfRequest message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns QuerySupplyOfRequest
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(
          r: $protobuf.Reader | Uint8Array,
          l?: number,
        ): cosmos.bank.v1beta1.QuerySupplyOfRequest;
      }

      /** Properties of a QuerySupplyOfResponse. */
      interface IQuerySupplyOfResponse {
        /** QuerySupplyOfResponse amount */
        amount?: cosmos.base.v1beta1.ICoin | null;
      }

      /** Represents a QuerySupplyOfResponse. */
      class QuerySupplyOfResponse implements IQuerySupplyOfResponse {
        /**
         * Constructs a new QuerySupplyOfResponse.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.bank.v1beta1.IQuerySupplyOfResponse);

        /** QuerySupplyOfResponse amount. */
        public amount?: cosmos.base.v1beta1.ICoin | null;

        /**
         * Creates a new QuerySupplyOfResponse instance using the specified properties.
         * @param [properties] Properties to set
         * @returns QuerySupplyOfResponse instance
         */
        public static create(
          properties?: cosmos.bank.v1beta1.IQuerySupplyOfResponse,
        ): cosmos.bank.v1beta1.QuerySupplyOfResponse;

        /**
         * Encodes the specified QuerySupplyOfResponse message. Does not implicitly {@link cosmos.bank.v1beta1.QuerySupplyOfResponse.verify|verify} messages.
         * @param m QuerySupplyOfResponse message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(
          m: cosmos.bank.v1beta1.IQuerySupplyOfResponse,
          w?: $protobuf.Writer,
        ): $protobuf.Writer;

        /**
         * Decodes a QuerySupplyOfResponse message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns QuerySupplyOfResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(
          r: $protobuf.Reader | Uint8Array,
          l?: number,
        ): cosmos.bank.v1beta1.QuerySupplyOfResponse;
      }

      /** Properties of a QueryParamsRequest. */
      interface IQueryParamsRequest {}

      /** Represents a QueryParamsRequest. */
      class QueryParamsRequest implements IQueryParamsRequest {
        /**
         * Constructs a new QueryParamsRequest.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.bank.v1beta1.IQueryParamsRequest);

        /**
         * Creates a new QueryParamsRequest instance using the specified properties.
         * @param [properties] Properties to set
         * @returns QueryParamsRequest instance
         */
        public static create(
          properties?: cosmos.bank.v1beta1.IQueryParamsRequest,
        ): cosmos.bank.v1beta1.QueryParamsRequest;

        /**
         * Encodes the specified QueryParamsRequest message. Does not implicitly {@link cosmos.bank.v1beta1.QueryParamsRequest.verify|verify} messages.
         * @param m QueryParamsRequest message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(
          m: cosmos.bank.v1beta1.IQueryParamsRequest,
          w?: $protobuf.Writer,
        ): $protobuf.Writer;

        /**
         * Decodes a QueryParamsRequest message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns QueryParamsRequest
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(
          r: $protobuf.Reader | Uint8Array,
          l?: number,
        ): cosmos.bank.v1beta1.QueryParamsRequest;
      }

      /** Properties of a QueryParamsResponse. */
      interface IQueryParamsResponse {
        /** QueryParamsResponse params */
        params?: cosmos.auth.v1beta1.IParams | null;
      }

      /** Represents a QueryParamsResponse. */
      class QueryParamsResponse implements IQueryParamsResponse {
        /**
         * Constructs a new QueryParamsResponse.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.bank.v1beta1.IQueryParamsResponse);

        /** QueryParamsResponse params. */
        public params?: cosmos.auth.v1beta1.IParams | null;

        /**
         * Creates a new QueryParamsResponse instance using the specified properties.
         * @param [properties] Properties to set
         * @returns QueryParamsResponse instance
         */
        public static create(
          properties?: cosmos.bank.v1beta1.IQueryParamsResponse,
        ): cosmos.bank.v1beta1.QueryParamsResponse;

        /**
         * Encodes the specified QueryParamsResponse message. Does not implicitly {@link cosmos.bank.v1beta1.QueryParamsResponse.verify|verify} messages.
         * @param m QueryParamsResponse message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(
          m: cosmos.bank.v1beta1.IQueryParamsResponse,
          w?: $protobuf.Writer,
        ): $protobuf.Writer;

        /**
         * Decodes a QueryParamsResponse message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns QueryParamsResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(
          r: $protobuf.Reader | Uint8Array,
          l?: number,
        ): cosmos.bank.v1beta1.QueryParamsResponse;
      }
    }
  }

  /** Namespace base. */
  namespace base {
    /** Namespace query. */
    namespace query {
      /** Namespace v1beta1. */
      namespace v1beta1 {
        /** Properties of a PageRequest. */
        interface IPageRequest {
          /** PageRequest key */
          key?: Uint8Array | null;

          /** PageRequest offset */
          offset?: Long | null;

          /** PageRequest limit */
          limit?: Long | null;

          /** PageRequest countTotal */
          countTotal?: boolean | null;
        }

        /** Represents a PageRequest. */
        class PageRequest implements IPageRequest {
          /**
           * Constructs a new PageRequest.
           * @param [p] Properties to set
           */
          constructor(p?: cosmos.base.query.v1beta1.IPageRequest);

          /** PageRequest key. */
          public key: Uint8Array;

          /** PageRequest offset. */
          public offset: Long;

          /** PageRequest limit. */
          public limit: Long;

          /** PageRequest countTotal. */
          public countTotal: boolean;

          /**
           * Creates a new PageRequest instance using the specified properties.
           * @param [properties] Properties to set
           * @returns PageRequest instance
           */
          public static create(
            properties?: cosmos.base.query.v1beta1.IPageRequest,
          ): cosmos.base.query.v1beta1.PageRequest;

          /**
           * Encodes the specified PageRequest message. Does not implicitly {@link cosmos.base.query.v1beta1.PageRequest.verify|verify} messages.
           * @param m PageRequest message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: cosmos.base.query.v1beta1.IPageRequest,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a PageRequest message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns PageRequest
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): cosmos.base.query.v1beta1.PageRequest;
        }

        /** Properties of a PageResponse. */
        interface IPageResponse {
          /** PageResponse nextKey */
          nextKey?: Uint8Array | null;

          /** PageResponse total */
          total?: Long | null;
        }

        /** Represents a PageResponse. */
        class PageResponse implements IPageResponse {
          /**
           * Constructs a new PageResponse.
           * @param [p] Properties to set
           */
          constructor(p?: cosmos.base.query.v1beta1.IPageResponse);

          /** PageResponse nextKey. */
          public nextKey: Uint8Array;

          /** PageResponse total. */
          public total: Long;

          /**
           * Creates a new PageResponse instance using the specified properties.
           * @param [properties] Properties to set
           * @returns PageResponse instance
           */
          public static create(
            properties?: cosmos.base.query.v1beta1.IPageResponse,
          ): cosmos.base.query.v1beta1.PageResponse;

          /**
           * Encodes the specified PageResponse message. Does not implicitly {@link cosmos.base.query.v1beta1.PageResponse.verify|verify} messages.
           * @param m PageResponse message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: cosmos.base.query.v1beta1.IPageResponse,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a PageResponse message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns PageResponse
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): cosmos.base.query.v1beta1.PageResponse;
        }
      }
    }

    /** Namespace v1beta1. */
    namespace v1beta1 {
      /** Properties of a Coin. */
      interface ICoin {
        /** Coin denom */
        denom?: string | null;

        /** Coin amount */
        amount?: string | null;
      }

      /** Represents a Coin. */
      class Coin implements ICoin {
        /**
         * Constructs a new Coin.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.base.v1beta1.ICoin);

        /** Coin denom. */
        public denom: string;

        /** Coin amount. */
        public amount: string;

        /**
         * Creates a new Coin instance using the specified properties.
         * @param [properties] Properties to set
         * @returns Coin instance
         */
        public static create(properties?: cosmos.base.v1beta1.ICoin): cosmos.base.v1beta1.Coin;

        /**
         * Encodes the specified Coin message. Does not implicitly {@link cosmos.base.v1beta1.Coin.verify|verify} messages.
         * @param m Coin message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(m: cosmos.base.v1beta1.ICoin, w?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a Coin message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns Coin
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(r: $protobuf.Reader | Uint8Array, l?: number): cosmos.base.v1beta1.Coin;
      }

      /** Properties of a DecCoin. */
      interface IDecCoin {
        /** DecCoin denom */
        denom?: string | null;

        /** DecCoin amount */
        amount?: string | null;
      }

      /** Represents a DecCoin. */
      class DecCoin implements IDecCoin {
        /**
         * Constructs a new DecCoin.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.base.v1beta1.IDecCoin);

        /** DecCoin denom. */
        public denom: string;

        /** DecCoin amount. */
        public amount: string;

        /**
         * Creates a new DecCoin instance using the specified properties.
         * @param [properties] Properties to set
         * @returns DecCoin instance
         */
        public static create(properties?: cosmos.base.v1beta1.IDecCoin): cosmos.base.v1beta1.DecCoin;

        /**
         * Encodes the specified DecCoin message. Does not implicitly {@link cosmos.base.v1beta1.DecCoin.verify|verify} messages.
         * @param m DecCoin message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(m: cosmos.base.v1beta1.IDecCoin, w?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a DecCoin message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns DecCoin
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(r: $protobuf.Reader | Uint8Array, l?: number): cosmos.base.v1beta1.DecCoin;
      }

      /** Properties of an IntProto. */
      interface IIntProto {
        /** IntProto int */
        int?: string | null;
      }

      /** Represents an IntProto. */
      class IntProto implements IIntProto {
        /**
         * Constructs a new IntProto.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.base.v1beta1.IIntProto);

        /** IntProto int. */
        public int: string;

        /**
         * Creates a new IntProto instance using the specified properties.
         * @param [properties] Properties to set
         * @returns IntProto instance
         */
        public static create(properties?: cosmos.base.v1beta1.IIntProto): cosmos.base.v1beta1.IntProto;

        /**
         * Encodes the specified IntProto message. Does not implicitly {@link cosmos.base.v1beta1.IntProto.verify|verify} messages.
         * @param m IntProto message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(m: cosmos.base.v1beta1.IIntProto, w?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes an IntProto message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns IntProto
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(r: $protobuf.Reader | Uint8Array, l?: number): cosmos.base.v1beta1.IntProto;
      }

      /** Properties of a DecProto. */
      interface IDecProto {
        /** DecProto dec */
        dec?: string | null;
      }

      /** Represents a DecProto. */
      class DecProto implements IDecProto {
        /**
         * Constructs a new DecProto.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.base.v1beta1.IDecProto);

        /** DecProto dec. */
        public dec: string;

        /**
         * Creates a new DecProto instance using the specified properties.
         * @param [properties] Properties to set
         * @returns DecProto instance
         */
        public static create(properties?: cosmos.base.v1beta1.IDecProto): cosmos.base.v1beta1.DecProto;

        /**
         * Encodes the specified DecProto message. Does not implicitly {@link cosmos.base.v1beta1.DecProto.verify|verify} messages.
         * @param m DecProto message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(m: cosmos.base.v1beta1.IDecProto, w?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a DecProto message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns DecProto
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(r: $protobuf.Reader | Uint8Array, l?: number): cosmos.base.v1beta1.DecProto;
      }
    }
  }

  /** Namespace crypto. */
  namespace crypto {
    /** Namespace multisig. */
    namespace multisig {
      /** Namespace v1beta1. */
      namespace v1beta1 {
        /** Properties of a MultiSignature. */
        interface IMultiSignature {
          /** MultiSignature signatures */
          signatures?: Uint8Array[] | null;
        }

        /** Represents a MultiSignature. */
        class MultiSignature implements IMultiSignature {
          /**
           * Constructs a new MultiSignature.
           * @param [p] Properties to set
           */
          constructor(p?: cosmos.crypto.multisig.v1beta1.IMultiSignature);

          /** MultiSignature signatures. */
          public signatures: Uint8Array[];

          /**
           * Creates a new MultiSignature instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MultiSignature instance
           */
          public static create(
            properties?: cosmos.crypto.multisig.v1beta1.IMultiSignature,
          ): cosmos.crypto.multisig.v1beta1.MultiSignature;

          /**
           * Encodes the specified MultiSignature message. Does not implicitly {@link cosmos.crypto.multisig.v1beta1.MultiSignature.verify|verify} messages.
           * @param m MultiSignature message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: cosmos.crypto.multisig.v1beta1.IMultiSignature,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a MultiSignature message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MultiSignature
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): cosmos.crypto.multisig.v1beta1.MultiSignature;
        }

        /** Properties of a CompactBitArray. */
        interface ICompactBitArray {
          /** CompactBitArray extraBitsStored */
          extraBitsStored?: number | null;

          /** CompactBitArray elems */
          elems?: Uint8Array | null;
        }

        /** Represents a CompactBitArray. */
        class CompactBitArray implements ICompactBitArray {
          /**
           * Constructs a new CompactBitArray.
           * @param [p] Properties to set
           */
          constructor(p?: cosmos.crypto.multisig.v1beta1.ICompactBitArray);

          /** CompactBitArray extraBitsStored. */
          public extraBitsStored: number;

          /** CompactBitArray elems. */
          public elems: Uint8Array;

          /**
           * Creates a new CompactBitArray instance using the specified properties.
           * @param [properties] Properties to set
           * @returns CompactBitArray instance
           */
          public static create(
            properties?: cosmos.crypto.multisig.v1beta1.ICompactBitArray,
          ): cosmos.crypto.multisig.v1beta1.CompactBitArray;

          /**
           * Encodes the specified CompactBitArray message. Does not implicitly {@link cosmos.crypto.multisig.v1beta1.CompactBitArray.verify|verify} messages.
           * @param m CompactBitArray message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: cosmos.crypto.multisig.v1beta1.ICompactBitArray,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a CompactBitArray message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns CompactBitArray
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): cosmos.crypto.multisig.v1beta1.CompactBitArray;
        }
      }
    }

    /** Namespace secp256k1. */
    namespace secp256k1 {
      /** Properties of a PubKey. */
      interface IPubKey {
        /** PubKey key */
        key?: Uint8Array | null;
      }

      /** Represents a PubKey. */
      class PubKey implements IPubKey {
        /**
         * Constructs a new PubKey.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.crypto.secp256k1.IPubKey);

        /** PubKey key. */
        public key: Uint8Array;

        /**
         * Creates a new PubKey instance using the specified properties.
         * @param [properties] Properties to set
         * @returns PubKey instance
         */
        public static create(properties?: cosmos.crypto.secp256k1.IPubKey): cosmos.crypto.secp256k1.PubKey;

        /**
         * Encodes the specified PubKey message. Does not implicitly {@link cosmos.crypto.secp256k1.PubKey.verify|verify} messages.
         * @param m PubKey message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(m: cosmos.crypto.secp256k1.IPubKey, w?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a PubKey message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns PubKey
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(r: $protobuf.Reader | Uint8Array, l?: number): cosmos.crypto.secp256k1.PubKey;
      }

      /** Properties of a PrivKey. */
      interface IPrivKey {
        /** PrivKey key */
        key?: Uint8Array | null;
      }

      /** Represents a PrivKey. */
      class PrivKey implements IPrivKey {
        /**
         * Constructs a new PrivKey.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.crypto.secp256k1.IPrivKey);

        /** PrivKey key. */
        public key: Uint8Array;

        /**
         * Creates a new PrivKey instance using the specified properties.
         * @param [properties] Properties to set
         * @returns PrivKey instance
         */
        public static create(properties?: cosmos.crypto.secp256k1.IPrivKey): cosmos.crypto.secp256k1.PrivKey;

        /**
         * Encodes the specified PrivKey message. Does not implicitly {@link cosmos.crypto.secp256k1.PrivKey.verify|verify} messages.
         * @param m PrivKey message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(m: cosmos.crypto.secp256k1.IPrivKey, w?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a PrivKey message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns PrivKey
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(r: $protobuf.Reader | Uint8Array, l?: number): cosmos.crypto.secp256k1.PrivKey;
      }
    }
  }

  /** Namespace tx. */
  namespace tx {
    /** Namespace signing. */
    namespace signing {
      /** Namespace v1beta1. */
      namespace v1beta1 {
        /** SignMode enum. */
        enum SignMode {
          SIGN_MODE_UNSPECIFIED = 0,
          SIGN_MODE_DIRECT = 1,
          SIGN_MODE_TEXTUAL = 2,
          SIGN_MODE_LEGACY_AMINO_JSON = 127,
        }

        /** Properties of a SignatureDescriptors. */
        interface ISignatureDescriptors {
          /** SignatureDescriptors signatures */
          signatures?: cosmos.tx.signing.v1beta1.ISignatureDescriptor[] | null;
        }

        /** Represents a SignatureDescriptors. */
        class SignatureDescriptors implements ISignatureDescriptors {
          /**
           * Constructs a new SignatureDescriptors.
           * @param [p] Properties to set
           */
          constructor(p?: cosmos.tx.signing.v1beta1.ISignatureDescriptors);

          /** SignatureDescriptors signatures. */
          public signatures: cosmos.tx.signing.v1beta1.ISignatureDescriptor[];

          /**
           * Creates a new SignatureDescriptors instance using the specified properties.
           * @param [properties] Properties to set
           * @returns SignatureDescriptors instance
           */
          public static create(
            properties?: cosmos.tx.signing.v1beta1.ISignatureDescriptors,
          ): cosmos.tx.signing.v1beta1.SignatureDescriptors;

          /**
           * Encodes the specified SignatureDescriptors message. Does not implicitly {@link cosmos.tx.signing.v1beta1.SignatureDescriptors.verify|verify} messages.
           * @param m SignatureDescriptors message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: cosmos.tx.signing.v1beta1.ISignatureDescriptors,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a SignatureDescriptors message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns SignatureDescriptors
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): cosmos.tx.signing.v1beta1.SignatureDescriptors;
        }

        /** Properties of a SignatureDescriptor. */
        interface ISignatureDescriptor {
          /** SignatureDescriptor publicKey */
          publicKey?: google.protobuf.IAny | null;

          /** SignatureDescriptor data */
          data?: cosmos.tx.signing.v1beta1.SignatureDescriptor.IData | null;

          /** SignatureDescriptor sequence */
          sequence?: Long | null;
        }

        /** Represents a SignatureDescriptor. */
        class SignatureDescriptor implements ISignatureDescriptor {
          /**
           * Constructs a new SignatureDescriptor.
           * @param [p] Properties to set
           */
          constructor(p?: cosmos.tx.signing.v1beta1.ISignatureDescriptor);

          /** SignatureDescriptor publicKey. */
          public publicKey?: google.protobuf.IAny | null;

          /** SignatureDescriptor data. */
          public data?: cosmos.tx.signing.v1beta1.SignatureDescriptor.IData | null;

          /** SignatureDescriptor sequence. */
          public sequence: Long;

          /**
           * Creates a new SignatureDescriptor instance using the specified properties.
           * @param [properties] Properties to set
           * @returns SignatureDescriptor instance
           */
          public static create(
            properties?: cosmos.tx.signing.v1beta1.ISignatureDescriptor,
          ): cosmos.tx.signing.v1beta1.SignatureDescriptor;

          /**
           * Encodes the specified SignatureDescriptor message. Does not implicitly {@link cosmos.tx.signing.v1beta1.SignatureDescriptor.verify|verify} messages.
           * @param m SignatureDescriptor message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: cosmos.tx.signing.v1beta1.ISignatureDescriptor,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a SignatureDescriptor message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns SignatureDescriptor
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): cosmos.tx.signing.v1beta1.SignatureDescriptor;
        }

        namespace SignatureDescriptor {
          /** Properties of a Data. */
          interface IData {
            /** Data single */
            single?: cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.ISingle | null;

            /** Data multi */
            multi?: cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.IMulti | null;
          }

          /** Represents a Data. */
          class Data implements IData {
            /**
             * Constructs a new Data.
             * @param [p] Properties to set
             */
            constructor(p?: cosmos.tx.signing.v1beta1.SignatureDescriptor.IData);

            /** Data single. */
            public single?: cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.ISingle | null;

            /** Data multi. */
            public multi?: cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.IMulti | null;

            /** Data sum. */
            public sum?: "single" | "multi";

            /**
             * Creates a new Data instance using the specified properties.
             * @param [properties] Properties to set
             * @returns Data instance
             */
            public static create(
              properties?: cosmos.tx.signing.v1beta1.SignatureDescriptor.IData,
            ): cosmos.tx.signing.v1beta1.SignatureDescriptor.Data;

            /**
             * Encodes the specified Data message. Does not implicitly {@link cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.verify|verify} messages.
             * @param m Data message or plain object to encode
             * @param [w] Writer to encode to
             * @returns Writer
             */
            public static encode(
              m: cosmos.tx.signing.v1beta1.SignatureDescriptor.IData,
              w?: $protobuf.Writer,
            ): $protobuf.Writer;

            /**
             * Decodes a Data message from the specified reader or buffer.
             * @param r Reader or buffer to decode from
             * @param [l] Message length if known beforehand
             * @returns Data
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(
              r: $protobuf.Reader | Uint8Array,
              l?: number,
            ): cosmos.tx.signing.v1beta1.SignatureDescriptor.Data;
          }

          namespace Data {
            /** Properties of a Single. */
            interface ISingle {
              /** Single mode */
              mode?: cosmos.tx.signing.v1beta1.SignMode | null;

              /** Single signature */
              signature?: Uint8Array | null;
            }

            /** Represents a Single. */
            class Single implements ISingle {
              /**
               * Constructs a new Single.
               * @param [p] Properties to set
               */
              constructor(p?: cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.ISingle);

              /** Single mode. */
              public mode: cosmos.tx.signing.v1beta1.SignMode;

              /** Single signature. */
              public signature: Uint8Array;

              /**
               * Creates a new Single instance using the specified properties.
               * @param [properties] Properties to set
               * @returns Single instance
               */
              public static create(
                properties?: cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.ISingle,
              ): cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.Single;

              /**
               * Encodes the specified Single message. Does not implicitly {@link cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.Single.verify|verify} messages.
               * @param m Single message or plain object to encode
               * @param [w] Writer to encode to
               * @returns Writer
               */
              public static encode(
                m: cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.ISingle,
                w?: $protobuf.Writer,
              ): $protobuf.Writer;

              /**
               * Decodes a Single message from the specified reader or buffer.
               * @param r Reader or buffer to decode from
               * @param [l] Message length if known beforehand
               * @returns Single
               * @throws {Error} If the payload is not a reader or valid buffer
               * @throws {$protobuf.util.ProtocolError} If required fields are missing
               */
              public static decode(
                r: $protobuf.Reader | Uint8Array,
                l?: number,
              ): cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.Single;
            }

            /** Properties of a Multi. */
            interface IMulti {
              /** Multi bitarray */
              bitarray?: cosmos.crypto.multisig.v1beta1.ICompactBitArray | null;

              /** Multi signatures */
              signatures?: cosmos.tx.signing.v1beta1.SignatureDescriptor.IData[] | null;
            }

            /** Represents a Multi. */
            class Multi implements IMulti {
              /**
               * Constructs a new Multi.
               * @param [p] Properties to set
               */
              constructor(p?: cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.IMulti);

              /** Multi bitarray. */
              public bitarray?: cosmos.crypto.multisig.v1beta1.ICompactBitArray | null;

              /** Multi signatures. */
              public signatures: cosmos.tx.signing.v1beta1.SignatureDescriptor.IData[];

              /**
               * Creates a new Multi instance using the specified properties.
               * @param [properties] Properties to set
               * @returns Multi instance
               */
              public static create(
                properties?: cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.IMulti,
              ): cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.Multi;

              /**
               * Encodes the specified Multi message. Does not implicitly {@link cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.Multi.verify|verify} messages.
               * @param m Multi message or plain object to encode
               * @param [w] Writer to encode to
               * @returns Writer
               */
              public static encode(
                m: cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.IMulti,
                w?: $protobuf.Writer,
              ): $protobuf.Writer;

              /**
               * Decodes a Multi message from the specified reader or buffer.
               * @param r Reader or buffer to decode from
               * @param [l] Message length if known beforehand
               * @returns Multi
               * @throws {Error} If the payload is not a reader or valid buffer
               * @throws {$protobuf.util.ProtocolError} If required fields are missing
               */
              public static decode(
                r: $protobuf.Reader | Uint8Array,
                l?: number,
              ): cosmos.tx.signing.v1beta1.SignatureDescriptor.Data.Multi;
            }
          }
        }
      }
    }

    /** Namespace v1beta1. */
    namespace v1beta1 {
      /** Properties of a Tx. */
      interface ITx {
        /** Tx body */
        body?: cosmos.tx.v1beta1.ITxBody | null;

        /** Tx authInfo */
        authInfo?: cosmos.tx.v1beta1.IAuthInfo | null;

        /** Tx signatures */
        signatures?: Uint8Array[] | null;
      }

      /** Represents a Tx. */
      class Tx implements ITx {
        /**
         * Constructs a new Tx.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.tx.v1beta1.ITx);

        /** Tx body. */
        public body?: cosmos.tx.v1beta1.ITxBody | null;

        /** Tx authInfo. */
        public authInfo?: cosmos.tx.v1beta1.IAuthInfo | null;

        /** Tx signatures. */
        public signatures: Uint8Array[];

        /**
         * Creates a new Tx instance using the specified properties.
         * @param [properties] Properties to set
         * @returns Tx instance
         */
        public static create(properties?: cosmos.tx.v1beta1.ITx): cosmos.tx.v1beta1.Tx;

        /**
         * Encodes the specified Tx message. Does not implicitly {@link cosmos.tx.v1beta1.Tx.verify|verify} messages.
         * @param m Tx message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(m: cosmos.tx.v1beta1.ITx, w?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a Tx message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns Tx
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(r: $protobuf.Reader | Uint8Array, l?: number): cosmos.tx.v1beta1.Tx;
      }

      /** Properties of a TxRaw. */
      interface ITxRaw {
        /** TxRaw bodyBytes */
        bodyBytes?: Uint8Array | null;

        /** TxRaw authInfoBytes */
        authInfoBytes?: Uint8Array | null;

        /** TxRaw signatures */
        signatures?: Uint8Array[] | null;
      }

      /** Represents a TxRaw. */
      class TxRaw implements ITxRaw {
        /**
         * Constructs a new TxRaw.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.tx.v1beta1.ITxRaw);

        /** TxRaw bodyBytes. */
        public bodyBytes: Uint8Array;

        /** TxRaw authInfoBytes. */
        public authInfoBytes: Uint8Array;

        /** TxRaw signatures. */
        public signatures: Uint8Array[];

        /**
         * Creates a new TxRaw instance using the specified properties.
         * @param [properties] Properties to set
         * @returns TxRaw instance
         */
        public static create(properties?: cosmos.tx.v1beta1.ITxRaw): cosmos.tx.v1beta1.TxRaw;

        /**
         * Encodes the specified TxRaw message. Does not implicitly {@link cosmos.tx.v1beta1.TxRaw.verify|verify} messages.
         * @param m TxRaw message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(m: cosmos.tx.v1beta1.ITxRaw, w?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a TxRaw message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns TxRaw
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(r: $protobuf.Reader | Uint8Array, l?: number): cosmos.tx.v1beta1.TxRaw;
      }

      /** Properties of a SignDoc. */
      interface ISignDoc {
        /** SignDoc bodyBytes */
        bodyBytes?: Uint8Array | null;

        /** SignDoc authInfoBytes */
        authInfoBytes?: Uint8Array | null;

        /** SignDoc chainId */
        chainId?: string | null;

        /** SignDoc accountNumber */
        accountNumber?: Long | null;
      }

      /** Represents a SignDoc. */
      class SignDoc implements ISignDoc {
        /**
         * Constructs a new SignDoc.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.tx.v1beta1.ISignDoc);

        /** SignDoc bodyBytes. */
        public bodyBytes: Uint8Array;

        /** SignDoc authInfoBytes. */
        public authInfoBytes: Uint8Array;

        /** SignDoc chainId. */
        public chainId: string;

        /** SignDoc accountNumber. */
        public accountNumber: Long;

        /**
         * Creates a new SignDoc instance using the specified properties.
         * @param [properties] Properties to set
         * @returns SignDoc instance
         */
        public static create(properties?: cosmos.tx.v1beta1.ISignDoc): cosmos.tx.v1beta1.SignDoc;

        /**
         * Encodes the specified SignDoc message. Does not implicitly {@link cosmos.tx.v1beta1.SignDoc.verify|verify} messages.
         * @param m SignDoc message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(m: cosmos.tx.v1beta1.ISignDoc, w?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a SignDoc message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns SignDoc
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(r: $protobuf.Reader | Uint8Array, l?: number): cosmos.tx.v1beta1.SignDoc;
      }

      /** Properties of a TxBody. */
      interface ITxBody {
        /** TxBody messages */
        messages?: google.protobuf.IAny[] | null;

        /** TxBody memo */
        memo?: string | null;

        /** TxBody timeoutHeight */
        timeoutHeight?: Long | null;

        /** TxBody extensionOptions */
        extensionOptions?: google.protobuf.IAny[] | null;

        /** TxBody nonCriticalExtensionOptions */
        nonCriticalExtensionOptions?: google.protobuf.IAny[] | null;
      }

      /** Represents a TxBody. */
      class TxBody implements ITxBody {
        /**
         * Constructs a new TxBody.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.tx.v1beta1.ITxBody);

        /** TxBody messages. */
        public messages: google.protobuf.IAny[];

        /** TxBody memo. */
        public memo: string;

        /** TxBody timeoutHeight. */
        public timeoutHeight: Long;

        /** TxBody extensionOptions. */
        public extensionOptions: google.protobuf.IAny[];

        /** TxBody nonCriticalExtensionOptions. */
        public nonCriticalExtensionOptions: google.protobuf.IAny[];

        /**
         * Creates a new TxBody instance using the specified properties.
         * @param [properties] Properties to set
         * @returns TxBody instance
         */
        public static create(properties?: cosmos.tx.v1beta1.ITxBody): cosmos.tx.v1beta1.TxBody;

        /**
         * Encodes the specified TxBody message. Does not implicitly {@link cosmos.tx.v1beta1.TxBody.verify|verify} messages.
         * @param m TxBody message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(m: cosmos.tx.v1beta1.ITxBody, w?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a TxBody message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns TxBody
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(r: $protobuf.Reader | Uint8Array, l?: number): cosmos.tx.v1beta1.TxBody;
      }

      /** Properties of an AuthInfo. */
      interface IAuthInfo {
        /** AuthInfo signerInfos */
        signerInfos?: cosmos.tx.v1beta1.ISignerInfo[] | null;

        /** AuthInfo fee */
        fee?: cosmos.tx.v1beta1.IFee | null;
      }

      /** Represents an AuthInfo. */
      class AuthInfo implements IAuthInfo {
        /**
         * Constructs a new AuthInfo.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.tx.v1beta1.IAuthInfo);

        /** AuthInfo signerInfos. */
        public signerInfos: cosmos.tx.v1beta1.ISignerInfo[];

        /** AuthInfo fee. */
        public fee?: cosmos.tx.v1beta1.IFee | null;

        /**
         * Creates a new AuthInfo instance using the specified properties.
         * @param [properties] Properties to set
         * @returns AuthInfo instance
         */
        public static create(properties?: cosmos.tx.v1beta1.IAuthInfo): cosmos.tx.v1beta1.AuthInfo;

        /**
         * Encodes the specified AuthInfo message. Does not implicitly {@link cosmos.tx.v1beta1.AuthInfo.verify|verify} messages.
         * @param m AuthInfo message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(m: cosmos.tx.v1beta1.IAuthInfo, w?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes an AuthInfo message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns AuthInfo
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(r: $protobuf.Reader | Uint8Array, l?: number): cosmos.tx.v1beta1.AuthInfo;
      }

      /** Properties of a SignerInfo. */
      interface ISignerInfo {
        /** SignerInfo publicKey */
        publicKey?: google.protobuf.IAny | null;

        /** SignerInfo modeInfo */
        modeInfo?: cosmos.tx.v1beta1.IModeInfo | null;

        /** SignerInfo sequence */
        sequence?: Long | null;
      }

      /** Represents a SignerInfo. */
      class SignerInfo implements ISignerInfo {
        /**
         * Constructs a new SignerInfo.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.tx.v1beta1.ISignerInfo);

        /** SignerInfo publicKey. */
        public publicKey?: google.protobuf.IAny | null;

        /** SignerInfo modeInfo. */
        public modeInfo?: cosmos.tx.v1beta1.IModeInfo | null;

        /** SignerInfo sequence. */
        public sequence: Long;

        /**
         * Creates a new SignerInfo instance using the specified properties.
         * @param [properties] Properties to set
         * @returns SignerInfo instance
         */
        public static create(properties?: cosmos.tx.v1beta1.ISignerInfo): cosmos.tx.v1beta1.SignerInfo;

        /**
         * Encodes the specified SignerInfo message. Does not implicitly {@link cosmos.tx.v1beta1.SignerInfo.verify|verify} messages.
         * @param m SignerInfo message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(m: cosmos.tx.v1beta1.ISignerInfo, w?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a SignerInfo message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns SignerInfo
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(r: $protobuf.Reader | Uint8Array, l?: number): cosmos.tx.v1beta1.SignerInfo;
      }

      /** Properties of a ModeInfo. */
      interface IModeInfo {
        /** ModeInfo single */
        single?: cosmos.tx.v1beta1.ModeInfo.ISingle | null;

        /** ModeInfo multi */
        multi?: cosmos.tx.v1beta1.ModeInfo.IMulti | null;
      }

      /** Represents a ModeInfo. */
      class ModeInfo implements IModeInfo {
        /**
         * Constructs a new ModeInfo.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.tx.v1beta1.IModeInfo);

        /** ModeInfo single. */
        public single?: cosmos.tx.v1beta1.ModeInfo.ISingle | null;

        /** ModeInfo multi. */
        public multi?: cosmos.tx.v1beta1.ModeInfo.IMulti | null;

        /** ModeInfo sum. */
        public sum?: "single" | "multi";

        /**
         * Creates a new ModeInfo instance using the specified properties.
         * @param [properties] Properties to set
         * @returns ModeInfo instance
         */
        public static create(properties?: cosmos.tx.v1beta1.IModeInfo): cosmos.tx.v1beta1.ModeInfo;

        /**
         * Encodes the specified ModeInfo message. Does not implicitly {@link cosmos.tx.v1beta1.ModeInfo.verify|verify} messages.
         * @param m ModeInfo message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(m: cosmos.tx.v1beta1.IModeInfo, w?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a ModeInfo message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns ModeInfo
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(r: $protobuf.Reader | Uint8Array, l?: number): cosmos.tx.v1beta1.ModeInfo;
      }

      namespace ModeInfo {
        /** Properties of a Single. */
        interface ISingle {
          /** Single mode */
          mode?: cosmos.tx.signing.v1beta1.SignMode | null;
        }

        /** Represents a Single. */
        class Single implements ISingle {
          /**
           * Constructs a new Single.
           * @param [p] Properties to set
           */
          constructor(p?: cosmos.tx.v1beta1.ModeInfo.ISingle);

          /** Single mode. */
          public mode: cosmos.tx.signing.v1beta1.SignMode;

          /**
           * Creates a new Single instance using the specified properties.
           * @param [properties] Properties to set
           * @returns Single instance
           */
          public static create(
            properties?: cosmos.tx.v1beta1.ModeInfo.ISingle,
          ): cosmos.tx.v1beta1.ModeInfo.Single;

          /**
           * Encodes the specified Single message. Does not implicitly {@link cosmos.tx.v1beta1.ModeInfo.Single.verify|verify} messages.
           * @param m Single message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(m: cosmos.tx.v1beta1.ModeInfo.ISingle, w?: $protobuf.Writer): $protobuf.Writer;

          /**
           * Decodes a Single message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns Single
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): cosmos.tx.v1beta1.ModeInfo.Single;
        }

        /** Properties of a Multi. */
        interface IMulti {
          /** Multi bitarray */
          bitarray?: cosmos.crypto.multisig.v1beta1.ICompactBitArray | null;

          /** Multi modeInfos */
          modeInfos?: cosmos.tx.v1beta1.IModeInfo[] | null;
        }

        /** Represents a Multi. */
        class Multi implements IMulti {
          /**
           * Constructs a new Multi.
           * @param [p] Properties to set
           */
          constructor(p?: cosmos.tx.v1beta1.ModeInfo.IMulti);

          /** Multi bitarray. */
          public bitarray?: cosmos.crypto.multisig.v1beta1.ICompactBitArray | null;

          /** Multi modeInfos. */
          public modeInfos: cosmos.tx.v1beta1.IModeInfo[];

          /**
           * Creates a new Multi instance using the specified properties.
           * @param [properties] Properties to set
           * @returns Multi instance
           */
          public static create(
            properties?: cosmos.tx.v1beta1.ModeInfo.IMulti,
          ): cosmos.tx.v1beta1.ModeInfo.Multi;

          /**
           * Encodes the specified Multi message. Does not implicitly {@link cosmos.tx.v1beta1.ModeInfo.Multi.verify|verify} messages.
           * @param m Multi message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(m: cosmos.tx.v1beta1.ModeInfo.IMulti, w?: $protobuf.Writer): $protobuf.Writer;

          /**
           * Decodes a Multi message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns Multi
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): cosmos.tx.v1beta1.ModeInfo.Multi;
        }
      }

      /** Properties of a Fee. */
      interface IFee {
        /** Fee amount */
        amount?: cosmos.base.v1beta1.ICoin[] | null;

        /** Fee gasLimit */
        gasLimit?: Long | null;

        /** Fee payer */
        payer?: string | null;
      }

      /** Represents a Fee. */
      class Fee implements IFee {
        /**
         * Constructs a new Fee.
         * @param [p] Properties to set
         */
        constructor(p?: cosmos.tx.v1beta1.IFee);

        /** Fee amount. */
        public amount: cosmos.base.v1beta1.ICoin[];

        /** Fee gasLimit. */
        public gasLimit: Long;

        /** Fee payer. */
        public payer: string;

        /**
         * Creates a new Fee instance using the specified properties.
         * @param [properties] Properties to set
         * @returns Fee instance
         */
        public static create(properties?: cosmos.tx.v1beta1.IFee): cosmos.tx.v1beta1.Fee;

        /**
         * Encodes the specified Fee message. Does not implicitly {@link cosmos.tx.v1beta1.Fee.verify|verify} messages.
         * @param m Fee message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(m: cosmos.tx.v1beta1.IFee, w?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a Fee message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns Fee
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(r: $protobuf.Reader | Uint8Array, l?: number): cosmos.tx.v1beta1.Fee;
      }
    }
  }
}

/** Namespace google. */
export namespace google {
  /** Namespace protobuf. */
  namespace protobuf {
    /** Properties of an Any. */
    interface IAny {
      /** Any type_url */
      type_url?: string | null;

      /** Any value */
      value?: Uint8Array | null;
    }

    /** Represents an Any. */
    class Any implements IAny {
      /**
       * Constructs a new Any.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.IAny);

      /** Any type_url. */
      public type_url: string;

      /** Any value. */
      public value: Uint8Array;

      /**
       * Creates a new Any instance using the specified properties.
       * @param [properties] Properties to set
       * @returns Any instance
       */
      public static create(properties?: google.protobuf.IAny): google.protobuf.Any;

      /**
       * Encodes the specified Any message. Does not implicitly {@link google.protobuf.Any.verify|verify} messages.
       * @param m Any message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.protobuf.IAny, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes an Any message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns Any
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): google.protobuf.Any;
    }

    /** Properties of a FileDescriptorSet. */
    interface IFileDescriptorSet {
      /** FileDescriptorSet file */
      file?: google.protobuf.IFileDescriptorProto[] | null;
    }

    /** Represents a FileDescriptorSet. */
    class FileDescriptorSet implements IFileDescriptorSet {
      /**
       * Constructs a new FileDescriptorSet.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.IFileDescriptorSet);

      /** FileDescriptorSet file. */
      public file: google.protobuf.IFileDescriptorProto[];

      /**
       * Creates a new FileDescriptorSet instance using the specified properties.
       * @param [properties] Properties to set
       * @returns FileDescriptorSet instance
       */
      public static create(
        properties?: google.protobuf.IFileDescriptorSet,
      ): google.protobuf.FileDescriptorSet;

      /**
       * Encodes the specified FileDescriptorSet message. Does not implicitly {@link google.protobuf.FileDescriptorSet.verify|verify} messages.
       * @param m FileDescriptorSet message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.protobuf.IFileDescriptorSet, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes a FileDescriptorSet message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns FileDescriptorSet
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): google.protobuf.FileDescriptorSet;
    }

    /** Properties of a FileDescriptorProto. */
    interface IFileDescriptorProto {
      /** FileDescriptorProto name */
      name?: string | null;

      /** FileDescriptorProto package */
      package?: string | null;

      /** FileDescriptorProto dependency */
      dependency?: string[] | null;

      /** FileDescriptorProto publicDependency */
      publicDependency?: number[] | null;

      /** FileDescriptorProto weakDependency */
      weakDependency?: number[] | null;

      /** FileDescriptorProto messageType */
      messageType?: google.protobuf.IDescriptorProto[] | null;

      /** FileDescriptorProto enumType */
      enumType?: google.protobuf.IEnumDescriptorProto[] | null;

      /** FileDescriptorProto service */
      service?: google.protobuf.IServiceDescriptorProto[] | null;

      /** FileDescriptorProto extension */
      extension?: google.protobuf.IFieldDescriptorProto[] | null;

      /** FileDescriptorProto options */
      options?: google.protobuf.IFileOptions | null;

      /** FileDescriptorProto sourceCodeInfo */
      sourceCodeInfo?: google.protobuf.ISourceCodeInfo | null;

      /** FileDescriptorProto syntax */
      syntax?: string | null;
    }

    /** Represents a FileDescriptorProto. */
    class FileDescriptorProto implements IFileDescriptorProto {
      /**
       * Constructs a new FileDescriptorProto.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.IFileDescriptorProto);

      /** FileDescriptorProto name. */
      public name: string;

      /** FileDescriptorProto package. */
      public package: string;

      /** FileDescriptorProto dependency. */
      public dependency: string[];

      /** FileDescriptorProto publicDependency. */
      public publicDependency: number[];

      /** FileDescriptorProto weakDependency. */
      public weakDependency: number[];

      /** FileDescriptorProto messageType. */
      public messageType: google.protobuf.IDescriptorProto[];

      /** FileDescriptorProto enumType. */
      public enumType: google.protobuf.IEnumDescriptorProto[];

      /** FileDescriptorProto service. */
      public service: google.protobuf.IServiceDescriptorProto[];

      /** FileDescriptorProto extension. */
      public extension: google.protobuf.IFieldDescriptorProto[];

      /** FileDescriptorProto options. */
      public options?: google.protobuf.IFileOptions | null;

      /** FileDescriptorProto sourceCodeInfo. */
      public sourceCodeInfo?: google.protobuf.ISourceCodeInfo | null;

      /** FileDescriptorProto syntax. */
      public syntax: string;

      /**
       * Creates a new FileDescriptorProto instance using the specified properties.
       * @param [properties] Properties to set
       * @returns FileDescriptorProto instance
       */
      public static create(
        properties?: google.protobuf.IFileDescriptorProto,
      ): google.protobuf.FileDescriptorProto;

      /**
       * Encodes the specified FileDescriptorProto message. Does not implicitly {@link google.protobuf.FileDescriptorProto.verify|verify} messages.
       * @param m FileDescriptorProto message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.protobuf.IFileDescriptorProto, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes a FileDescriptorProto message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns FileDescriptorProto
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): google.protobuf.FileDescriptorProto;
    }

    /** Properties of a DescriptorProto. */
    interface IDescriptorProto {
      /** DescriptorProto name */
      name?: string | null;

      /** DescriptorProto field */
      field?: google.protobuf.IFieldDescriptorProto[] | null;

      /** DescriptorProto extension */
      extension?: google.protobuf.IFieldDescriptorProto[] | null;

      /** DescriptorProto nestedType */
      nestedType?: google.protobuf.IDescriptorProto[] | null;

      /** DescriptorProto enumType */
      enumType?: google.protobuf.IEnumDescriptorProto[] | null;

      /** DescriptorProto extensionRange */
      extensionRange?: google.protobuf.DescriptorProto.IExtensionRange[] | null;

      /** DescriptorProto oneofDecl */
      oneofDecl?: google.protobuf.IOneofDescriptorProto[] | null;

      /** DescriptorProto options */
      options?: google.protobuf.IMessageOptions | null;

      /** DescriptorProto reservedRange */
      reservedRange?: google.protobuf.DescriptorProto.IReservedRange[] | null;

      /** DescriptorProto reservedName */
      reservedName?: string[] | null;
    }

    /** Represents a DescriptorProto. */
    class DescriptorProto implements IDescriptorProto {
      /**
       * Constructs a new DescriptorProto.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.IDescriptorProto);

      /** DescriptorProto name. */
      public name: string;

      /** DescriptorProto field. */
      public field: google.protobuf.IFieldDescriptorProto[];

      /** DescriptorProto extension. */
      public extension: google.protobuf.IFieldDescriptorProto[];

      /** DescriptorProto nestedType. */
      public nestedType: google.protobuf.IDescriptorProto[];

      /** DescriptorProto enumType. */
      public enumType: google.protobuf.IEnumDescriptorProto[];

      /** DescriptorProto extensionRange. */
      public extensionRange: google.protobuf.DescriptorProto.IExtensionRange[];

      /** DescriptorProto oneofDecl. */
      public oneofDecl: google.protobuf.IOneofDescriptorProto[];

      /** DescriptorProto options. */
      public options?: google.protobuf.IMessageOptions | null;

      /** DescriptorProto reservedRange. */
      public reservedRange: google.protobuf.DescriptorProto.IReservedRange[];

      /** DescriptorProto reservedName. */
      public reservedName: string[];

      /**
       * Creates a new DescriptorProto instance using the specified properties.
       * @param [properties] Properties to set
       * @returns DescriptorProto instance
       */
      public static create(properties?: google.protobuf.IDescriptorProto): google.protobuf.DescriptorProto;

      /**
       * Encodes the specified DescriptorProto message. Does not implicitly {@link google.protobuf.DescriptorProto.verify|verify} messages.
       * @param m DescriptorProto message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.protobuf.IDescriptorProto, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes a DescriptorProto message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns DescriptorProto
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): google.protobuf.DescriptorProto;
    }

    namespace DescriptorProto {
      /** Properties of an ExtensionRange. */
      interface IExtensionRange {
        /** ExtensionRange start */
        start?: number | null;

        /** ExtensionRange end */
        end?: number | null;
      }

      /** Represents an ExtensionRange. */
      class ExtensionRange implements IExtensionRange {
        /**
         * Constructs a new ExtensionRange.
         * @param [p] Properties to set
         */
        constructor(p?: google.protobuf.DescriptorProto.IExtensionRange);

        /** ExtensionRange start. */
        public start: number;

        /** ExtensionRange end. */
        public end: number;

        /**
         * Creates a new ExtensionRange instance using the specified properties.
         * @param [properties] Properties to set
         * @returns ExtensionRange instance
         */
        public static create(
          properties?: google.protobuf.DescriptorProto.IExtensionRange,
        ): google.protobuf.DescriptorProto.ExtensionRange;

        /**
         * Encodes the specified ExtensionRange message. Does not implicitly {@link google.protobuf.DescriptorProto.ExtensionRange.verify|verify} messages.
         * @param m ExtensionRange message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(
          m: google.protobuf.DescriptorProto.IExtensionRange,
          w?: $protobuf.Writer,
        ): $protobuf.Writer;

        /**
         * Decodes an ExtensionRange message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns ExtensionRange
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(
          r: $protobuf.Reader | Uint8Array,
          l?: number,
        ): google.protobuf.DescriptorProto.ExtensionRange;
      }

      /** Properties of a ReservedRange. */
      interface IReservedRange {
        /** ReservedRange start */
        start?: number | null;

        /** ReservedRange end */
        end?: number | null;
      }

      /** Represents a ReservedRange. */
      class ReservedRange implements IReservedRange {
        /**
         * Constructs a new ReservedRange.
         * @param [p] Properties to set
         */
        constructor(p?: google.protobuf.DescriptorProto.IReservedRange);

        /** ReservedRange start. */
        public start: number;

        /** ReservedRange end. */
        public end: number;

        /**
         * Creates a new ReservedRange instance using the specified properties.
         * @param [properties] Properties to set
         * @returns ReservedRange instance
         */
        public static create(
          properties?: google.protobuf.DescriptorProto.IReservedRange,
        ): google.protobuf.DescriptorProto.ReservedRange;

        /**
         * Encodes the specified ReservedRange message. Does not implicitly {@link google.protobuf.DescriptorProto.ReservedRange.verify|verify} messages.
         * @param m ReservedRange message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(
          m: google.protobuf.DescriptorProto.IReservedRange,
          w?: $protobuf.Writer,
        ): $protobuf.Writer;

        /**
         * Decodes a ReservedRange message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns ReservedRange
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(
          r: $protobuf.Reader | Uint8Array,
          l?: number,
        ): google.protobuf.DescriptorProto.ReservedRange;
      }
    }

    /** Properties of a FieldDescriptorProto. */
    interface IFieldDescriptorProto {
      /** FieldDescriptorProto name */
      name?: string | null;

      /** FieldDescriptorProto number */
      number?: number | null;

      /** FieldDescriptorProto label */
      label?: google.protobuf.FieldDescriptorProto.Label | null;

      /** FieldDescriptorProto type */
      type?: google.protobuf.FieldDescriptorProto.Type | null;

      /** FieldDescriptorProto typeName */
      typeName?: string | null;

      /** FieldDescriptorProto extendee */
      extendee?: string | null;

      /** FieldDescriptorProto defaultValue */
      defaultValue?: string | null;

      /** FieldDescriptorProto oneofIndex */
      oneofIndex?: number | null;

      /** FieldDescriptorProto jsonName */
      jsonName?: string | null;

      /** FieldDescriptorProto options */
      options?: google.protobuf.IFieldOptions | null;
    }

    /** Represents a FieldDescriptorProto. */
    class FieldDescriptorProto implements IFieldDescriptorProto {
      /**
       * Constructs a new FieldDescriptorProto.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.IFieldDescriptorProto);

      /** FieldDescriptorProto name. */
      public name: string;

      /** FieldDescriptorProto number. */
      public number: number;

      /** FieldDescriptorProto label. */
      public label: google.protobuf.FieldDescriptorProto.Label;

      /** FieldDescriptorProto type. */
      public type: google.protobuf.FieldDescriptorProto.Type;

      /** FieldDescriptorProto typeName. */
      public typeName: string;

      /** FieldDescriptorProto extendee. */
      public extendee: string;

      /** FieldDescriptorProto defaultValue. */
      public defaultValue: string;

      /** FieldDescriptorProto oneofIndex. */
      public oneofIndex: number;

      /** FieldDescriptorProto jsonName. */
      public jsonName: string;

      /** FieldDescriptorProto options. */
      public options?: google.protobuf.IFieldOptions | null;

      /**
       * Creates a new FieldDescriptorProto instance using the specified properties.
       * @param [properties] Properties to set
       * @returns FieldDescriptorProto instance
       */
      public static create(
        properties?: google.protobuf.IFieldDescriptorProto,
      ): google.protobuf.FieldDescriptorProto;

      /**
       * Encodes the specified FieldDescriptorProto message. Does not implicitly {@link google.protobuf.FieldDescriptorProto.verify|verify} messages.
       * @param m FieldDescriptorProto message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.protobuf.IFieldDescriptorProto, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes a FieldDescriptorProto message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns FieldDescriptorProto
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(
        r: $protobuf.Reader | Uint8Array,
        l?: number,
      ): google.protobuf.FieldDescriptorProto;
    }

    namespace FieldDescriptorProto {
      /** Type enum. */
      enum Type {
        TYPE_DOUBLE = 1,
        TYPE_FLOAT = 2,
        TYPE_INT64 = 3,
        TYPE_UINT64 = 4,
        TYPE_INT32 = 5,
        TYPE_FIXED64 = 6,
        TYPE_FIXED32 = 7,
        TYPE_BOOL = 8,
        TYPE_STRING = 9,
        TYPE_GROUP = 10,
        TYPE_MESSAGE = 11,
        TYPE_BYTES = 12,
        TYPE_UINT32 = 13,
        TYPE_ENUM = 14,
        TYPE_SFIXED32 = 15,
        TYPE_SFIXED64 = 16,
        TYPE_SINT32 = 17,
        TYPE_SINT64 = 18,
      }

      /** Label enum. */
      enum Label {
        LABEL_OPTIONAL = 1,
        LABEL_REQUIRED = 2,
        LABEL_REPEATED = 3,
      }
    }

    /** Properties of an OneofDescriptorProto. */
    interface IOneofDescriptorProto {
      /** OneofDescriptorProto name */
      name?: string | null;

      /** OneofDescriptorProto options */
      options?: google.protobuf.IOneofOptions | null;
    }

    /** Represents an OneofDescriptorProto. */
    class OneofDescriptorProto implements IOneofDescriptorProto {
      /**
       * Constructs a new OneofDescriptorProto.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.IOneofDescriptorProto);

      /** OneofDescriptorProto name. */
      public name: string;

      /** OneofDescriptorProto options. */
      public options?: google.protobuf.IOneofOptions | null;

      /**
       * Creates a new OneofDescriptorProto instance using the specified properties.
       * @param [properties] Properties to set
       * @returns OneofDescriptorProto instance
       */
      public static create(
        properties?: google.protobuf.IOneofDescriptorProto,
      ): google.protobuf.OneofDescriptorProto;

      /**
       * Encodes the specified OneofDescriptorProto message. Does not implicitly {@link google.protobuf.OneofDescriptorProto.verify|verify} messages.
       * @param m OneofDescriptorProto message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.protobuf.IOneofDescriptorProto, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes an OneofDescriptorProto message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns OneofDescriptorProto
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(
        r: $protobuf.Reader | Uint8Array,
        l?: number,
      ): google.protobuf.OneofDescriptorProto;
    }

    /** Properties of an EnumDescriptorProto. */
    interface IEnumDescriptorProto {
      /** EnumDescriptorProto name */
      name?: string | null;

      /** EnumDescriptorProto value */
      value?: google.protobuf.IEnumValueDescriptorProto[] | null;

      /** EnumDescriptorProto options */
      options?: google.protobuf.IEnumOptions | null;
    }

    /** Represents an EnumDescriptorProto. */
    class EnumDescriptorProto implements IEnumDescriptorProto {
      /**
       * Constructs a new EnumDescriptorProto.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.IEnumDescriptorProto);

      /** EnumDescriptorProto name. */
      public name: string;

      /** EnumDescriptorProto value. */
      public value: google.protobuf.IEnumValueDescriptorProto[];

      /** EnumDescriptorProto options. */
      public options?: google.protobuf.IEnumOptions | null;

      /**
       * Creates a new EnumDescriptorProto instance using the specified properties.
       * @param [properties] Properties to set
       * @returns EnumDescriptorProto instance
       */
      public static create(
        properties?: google.protobuf.IEnumDescriptorProto,
      ): google.protobuf.EnumDescriptorProto;

      /**
       * Encodes the specified EnumDescriptorProto message. Does not implicitly {@link google.protobuf.EnumDescriptorProto.verify|verify} messages.
       * @param m EnumDescriptorProto message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.protobuf.IEnumDescriptorProto, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes an EnumDescriptorProto message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns EnumDescriptorProto
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): google.protobuf.EnumDescriptorProto;
    }

    /** Properties of an EnumValueDescriptorProto. */
    interface IEnumValueDescriptorProto {
      /** EnumValueDescriptorProto name */
      name?: string | null;

      /** EnumValueDescriptorProto number */
      number?: number | null;

      /** EnumValueDescriptorProto options */
      options?: google.protobuf.IEnumValueOptions | null;
    }

    /** Represents an EnumValueDescriptorProto. */
    class EnumValueDescriptorProto implements IEnumValueDescriptorProto {
      /**
       * Constructs a new EnumValueDescriptorProto.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.IEnumValueDescriptorProto);

      /** EnumValueDescriptorProto name. */
      public name: string;

      /** EnumValueDescriptorProto number. */
      public number: number;

      /** EnumValueDescriptorProto options. */
      public options?: google.protobuf.IEnumValueOptions | null;

      /**
       * Creates a new EnumValueDescriptorProto instance using the specified properties.
       * @param [properties] Properties to set
       * @returns EnumValueDescriptorProto instance
       */
      public static create(
        properties?: google.protobuf.IEnumValueDescriptorProto,
      ): google.protobuf.EnumValueDescriptorProto;

      /**
       * Encodes the specified EnumValueDescriptorProto message. Does not implicitly {@link google.protobuf.EnumValueDescriptorProto.verify|verify} messages.
       * @param m EnumValueDescriptorProto message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(
        m: google.protobuf.IEnumValueDescriptorProto,
        w?: $protobuf.Writer,
      ): $protobuf.Writer;

      /**
       * Decodes an EnumValueDescriptorProto message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns EnumValueDescriptorProto
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(
        r: $protobuf.Reader | Uint8Array,
        l?: number,
      ): google.protobuf.EnumValueDescriptorProto;
    }

    /** Properties of a ServiceDescriptorProto. */
    interface IServiceDescriptorProto {
      /** ServiceDescriptorProto name */
      name?: string | null;

      /** ServiceDescriptorProto method */
      method?: google.protobuf.IMethodDescriptorProto[] | null;

      /** ServiceDescriptorProto options */
      options?: google.protobuf.IServiceOptions | null;
    }

    /** Represents a ServiceDescriptorProto. */
    class ServiceDescriptorProto implements IServiceDescriptorProto {
      /**
       * Constructs a new ServiceDescriptorProto.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.IServiceDescriptorProto);

      /** ServiceDescriptorProto name. */
      public name: string;

      /** ServiceDescriptorProto method. */
      public method: google.protobuf.IMethodDescriptorProto[];

      /** ServiceDescriptorProto options. */
      public options?: google.protobuf.IServiceOptions | null;

      /**
       * Creates a new ServiceDescriptorProto instance using the specified properties.
       * @param [properties] Properties to set
       * @returns ServiceDescriptorProto instance
       */
      public static create(
        properties?: google.protobuf.IServiceDescriptorProto,
      ): google.protobuf.ServiceDescriptorProto;

      /**
       * Encodes the specified ServiceDescriptorProto message. Does not implicitly {@link google.protobuf.ServiceDescriptorProto.verify|verify} messages.
       * @param m ServiceDescriptorProto message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(
        m: google.protobuf.IServiceDescriptorProto,
        w?: $protobuf.Writer,
      ): $protobuf.Writer;

      /**
       * Decodes a ServiceDescriptorProto message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns ServiceDescriptorProto
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(
        r: $protobuf.Reader | Uint8Array,
        l?: number,
      ): google.protobuf.ServiceDescriptorProto;
    }

    /** Properties of a MethodDescriptorProto. */
    interface IMethodDescriptorProto {
      /** MethodDescriptorProto name */
      name?: string | null;

      /** MethodDescriptorProto inputType */
      inputType?: string | null;

      /** MethodDescriptorProto outputType */
      outputType?: string | null;

      /** MethodDescriptorProto options */
      options?: google.protobuf.IMethodOptions | null;

      /** MethodDescriptorProto clientStreaming */
      clientStreaming?: boolean | null;

      /** MethodDescriptorProto serverStreaming */
      serverStreaming?: boolean | null;
    }

    /** Represents a MethodDescriptorProto. */
    class MethodDescriptorProto implements IMethodDescriptorProto {
      /**
       * Constructs a new MethodDescriptorProto.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.IMethodDescriptorProto);

      /** MethodDescriptorProto name. */
      public name: string;

      /** MethodDescriptorProto inputType. */
      public inputType: string;

      /** MethodDescriptorProto outputType. */
      public outputType: string;

      /** MethodDescriptorProto options. */
      public options?: google.protobuf.IMethodOptions | null;

      /** MethodDescriptorProto clientStreaming. */
      public clientStreaming: boolean;

      /** MethodDescriptorProto serverStreaming. */
      public serverStreaming: boolean;

      /**
       * Creates a new MethodDescriptorProto instance using the specified properties.
       * @param [properties] Properties to set
       * @returns MethodDescriptorProto instance
       */
      public static create(
        properties?: google.protobuf.IMethodDescriptorProto,
      ): google.protobuf.MethodDescriptorProto;

      /**
       * Encodes the specified MethodDescriptorProto message. Does not implicitly {@link google.protobuf.MethodDescriptorProto.verify|verify} messages.
       * @param m MethodDescriptorProto message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.protobuf.IMethodDescriptorProto, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes a MethodDescriptorProto message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns MethodDescriptorProto
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(
        r: $protobuf.Reader | Uint8Array,
        l?: number,
      ): google.protobuf.MethodDescriptorProto;
    }

    /** Properties of a FileOptions. */
    interface IFileOptions {
      /** FileOptions javaPackage */
      javaPackage?: string | null;

      /** FileOptions javaOuterClassname */
      javaOuterClassname?: string | null;

      /** FileOptions javaMultipleFiles */
      javaMultipleFiles?: boolean | null;

      /** FileOptions javaGenerateEqualsAndHash */
      javaGenerateEqualsAndHash?: boolean | null;

      /** FileOptions javaStringCheckUtf8 */
      javaStringCheckUtf8?: boolean | null;

      /** FileOptions optimizeFor */
      optimizeFor?: google.protobuf.FileOptions.OptimizeMode | null;

      /** FileOptions goPackage */
      goPackage?: string | null;

      /** FileOptions ccGenericServices */
      ccGenericServices?: boolean | null;

      /** FileOptions javaGenericServices */
      javaGenericServices?: boolean | null;

      /** FileOptions pyGenericServices */
      pyGenericServices?: boolean | null;

      /** FileOptions deprecated */
      deprecated?: boolean | null;

      /** FileOptions ccEnableArenas */
      ccEnableArenas?: boolean | null;

      /** FileOptions objcClassPrefix */
      objcClassPrefix?: string | null;

      /** FileOptions csharpNamespace */
      csharpNamespace?: string | null;

      /** FileOptions uninterpretedOption */
      uninterpretedOption?: google.protobuf.IUninterpretedOption[] | null;
    }

    /** Represents a FileOptions. */
    class FileOptions implements IFileOptions {
      /**
       * Constructs a new FileOptions.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.IFileOptions);

      /** FileOptions javaPackage. */
      public javaPackage: string;

      /** FileOptions javaOuterClassname. */
      public javaOuterClassname: string;

      /** FileOptions javaMultipleFiles. */
      public javaMultipleFiles: boolean;

      /** FileOptions javaGenerateEqualsAndHash. */
      public javaGenerateEqualsAndHash: boolean;

      /** FileOptions javaStringCheckUtf8. */
      public javaStringCheckUtf8: boolean;

      /** FileOptions optimizeFor. */
      public optimizeFor: google.protobuf.FileOptions.OptimizeMode;

      /** FileOptions goPackage. */
      public goPackage: string;

      /** FileOptions ccGenericServices. */
      public ccGenericServices: boolean;

      /** FileOptions javaGenericServices. */
      public javaGenericServices: boolean;

      /** FileOptions pyGenericServices. */
      public pyGenericServices: boolean;

      /** FileOptions deprecated. */
      public deprecated: boolean;

      /** FileOptions ccEnableArenas. */
      public ccEnableArenas: boolean;

      /** FileOptions objcClassPrefix. */
      public objcClassPrefix: string;

      /** FileOptions csharpNamespace. */
      public csharpNamespace: string;

      /** FileOptions uninterpretedOption. */
      public uninterpretedOption: google.protobuf.IUninterpretedOption[];

      /**
       * Creates a new FileOptions instance using the specified properties.
       * @param [properties] Properties to set
       * @returns FileOptions instance
       */
      public static create(properties?: google.protobuf.IFileOptions): google.protobuf.FileOptions;

      /**
       * Encodes the specified FileOptions message. Does not implicitly {@link google.protobuf.FileOptions.verify|verify} messages.
       * @param m FileOptions message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.protobuf.IFileOptions, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes a FileOptions message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns FileOptions
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): google.protobuf.FileOptions;
    }

    namespace FileOptions {
      /** OptimizeMode enum. */
      enum OptimizeMode {
        SPEED = 1,
        CODE_SIZE = 2,
        LITE_RUNTIME = 3,
      }
    }

    /** Properties of a MessageOptions. */
    interface IMessageOptions {
      /** MessageOptions messageSetWireFormat */
      messageSetWireFormat?: boolean | null;

      /** MessageOptions noStandardDescriptorAccessor */
      noStandardDescriptorAccessor?: boolean | null;

      /** MessageOptions deprecated */
      deprecated?: boolean | null;

      /** MessageOptions mapEntry */
      mapEntry?: boolean | null;

      /** MessageOptions uninterpretedOption */
      uninterpretedOption?: google.protobuf.IUninterpretedOption[] | null;
    }

    /** Represents a MessageOptions. */
    class MessageOptions implements IMessageOptions {
      /**
       * Constructs a new MessageOptions.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.IMessageOptions);

      /** MessageOptions messageSetWireFormat. */
      public messageSetWireFormat: boolean;

      /** MessageOptions noStandardDescriptorAccessor. */
      public noStandardDescriptorAccessor: boolean;

      /** MessageOptions deprecated. */
      public deprecated: boolean;

      /** MessageOptions mapEntry. */
      public mapEntry: boolean;

      /** MessageOptions uninterpretedOption. */
      public uninterpretedOption: google.protobuf.IUninterpretedOption[];

      /**
       * Creates a new MessageOptions instance using the specified properties.
       * @param [properties] Properties to set
       * @returns MessageOptions instance
       */
      public static create(properties?: google.protobuf.IMessageOptions): google.protobuf.MessageOptions;

      /**
       * Encodes the specified MessageOptions message. Does not implicitly {@link google.protobuf.MessageOptions.verify|verify} messages.
       * @param m MessageOptions message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.protobuf.IMessageOptions, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes a MessageOptions message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns MessageOptions
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): google.protobuf.MessageOptions;
    }

    /** Properties of a FieldOptions. */
    interface IFieldOptions {
      /** FieldOptions ctype */
      ctype?: google.protobuf.FieldOptions.CType | null;

      /** FieldOptions packed */
      packed?: boolean | null;

      /** FieldOptions jstype */
      jstype?: google.protobuf.FieldOptions.JSType | null;

      /** FieldOptions lazy */
      lazy?: boolean | null;

      /** FieldOptions deprecated */
      deprecated?: boolean | null;

      /** FieldOptions weak */
      weak?: boolean | null;

      /** FieldOptions uninterpretedOption */
      uninterpretedOption?: google.protobuf.IUninterpretedOption[] | null;
    }

    /** Represents a FieldOptions. */
    class FieldOptions implements IFieldOptions {
      /**
       * Constructs a new FieldOptions.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.IFieldOptions);

      /** FieldOptions ctype. */
      public ctype: google.protobuf.FieldOptions.CType;

      /** FieldOptions packed. */
      public packed: boolean;

      /** FieldOptions jstype. */
      public jstype: google.protobuf.FieldOptions.JSType;

      /** FieldOptions lazy. */
      public lazy: boolean;

      /** FieldOptions deprecated. */
      public deprecated: boolean;

      /** FieldOptions weak. */
      public weak: boolean;

      /** FieldOptions uninterpretedOption. */
      public uninterpretedOption: google.protobuf.IUninterpretedOption[];

      /**
       * Creates a new FieldOptions instance using the specified properties.
       * @param [properties] Properties to set
       * @returns FieldOptions instance
       */
      public static create(properties?: google.protobuf.IFieldOptions): google.protobuf.FieldOptions;

      /**
       * Encodes the specified FieldOptions message. Does not implicitly {@link google.protobuf.FieldOptions.verify|verify} messages.
       * @param m FieldOptions message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.protobuf.IFieldOptions, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes a FieldOptions message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns FieldOptions
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): google.protobuf.FieldOptions;
    }

    namespace FieldOptions {
      /** CType enum. */
      enum CType {
        STRING = 0,
        CORD = 1,
        STRING_PIECE = 2,
      }

      /** JSType enum. */
      enum JSType {
        JS_NORMAL = 0,
        JS_STRING = 1,
        JS_NUMBER = 2,
      }
    }

    /** Properties of an OneofOptions. */
    interface IOneofOptions {
      /** OneofOptions uninterpretedOption */
      uninterpretedOption?: google.protobuf.IUninterpretedOption[] | null;
    }

    /** Represents an OneofOptions. */
    class OneofOptions implements IOneofOptions {
      /**
       * Constructs a new OneofOptions.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.IOneofOptions);

      /** OneofOptions uninterpretedOption. */
      public uninterpretedOption: google.protobuf.IUninterpretedOption[];

      /**
       * Creates a new OneofOptions instance using the specified properties.
       * @param [properties] Properties to set
       * @returns OneofOptions instance
       */
      public static create(properties?: google.protobuf.IOneofOptions): google.protobuf.OneofOptions;

      /**
       * Encodes the specified OneofOptions message. Does not implicitly {@link google.protobuf.OneofOptions.verify|verify} messages.
       * @param m OneofOptions message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.protobuf.IOneofOptions, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes an OneofOptions message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns OneofOptions
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): google.protobuf.OneofOptions;
    }

    /** Properties of an EnumOptions. */
    interface IEnumOptions {
      /** EnumOptions allowAlias */
      allowAlias?: boolean | null;

      /** EnumOptions deprecated */
      deprecated?: boolean | null;

      /** EnumOptions uninterpretedOption */
      uninterpretedOption?: google.protobuf.IUninterpretedOption[] | null;
    }

    /** Represents an EnumOptions. */
    class EnumOptions implements IEnumOptions {
      /**
       * Constructs a new EnumOptions.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.IEnumOptions);

      /** EnumOptions allowAlias. */
      public allowAlias: boolean;

      /** EnumOptions deprecated. */
      public deprecated: boolean;

      /** EnumOptions uninterpretedOption. */
      public uninterpretedOption: google.protobuf.IUninterpretedOption[];

      /**
       * Creates a new EnumOptions instance using the specified properties.
       * @param [properties] Properties to set
       * @returns EnumOptions instance
       */
      public static create(properties?: google.protobuf.IEnumOptions): google.protobuf.EnumOptions;

      /**
       * Encodes the specified EnumOptions message. Does not implicitly {@link google.protobuf.EnumOptions.verify|verify} messages.
       * @param m EnumOptions message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.protobuf.IEnumOptions, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes an EnumOptions message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns EnumOptions
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): google.protobuf.EnumOptions;
    }

    /** Properties of an EnumValueOptions. */
    interface IEnumValueOptions {
      /** EnumValueOptions deprecated */
      deprecated?: boolean | null;

      /** EnumValueOptions uninterpretedOption */
      uninterpretedOption?: google.protobuf.IUninterpretedOption[] | null;
    }

    /** Represents an EnumValueOptions. */
    class EnumValueOptions implements IEnumValueOptions {
      /**
       * Constructs a new EnumValueOptions.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.IEnumValueOptions);

      /** EnumValueOptions deprecated. */
      public deprecated: boolean;

      /** EnumValueOptions uninterpretedOption. */
      public uninterpretedOption: google.protobuf.IUninterpretedOption[];

      /**
       * Creates a new EnumValueOptions instance using the specified properties.
       * @param [properties] Properties to set
       * @returns EnumValueOptions instance
       */
      public static create(properties?: google.protobuf.IEnumValueOptions): google.protobuf.EnumValueOptions;

      /**
       * Encodes the specified EnumValueOptions message. Does not implicitly {@link google.protobuf.EnumValueOptions.verify|verify} messages.
       * @param m EnumValueOptions message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.protobuf.IEnumValueOptions, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes an EnumValueOptions message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns EnumValueOptions
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): google.protobuf.EnumValueOptions;
    }

    /** Properties of a ServiceOptions. */
    interface IServiceOptions {
      /** ServiceOptions deprecated */
      deprecated?: boolean | null;

      /** ServiceOptions uninterpretedOption */
      uninterpretedOption?: google.protobuf.IUninterpretedOption[] | null;
    }

    /** Represents a ServiceOptions. */
    class ServiceOptions implements IServiceOptions {
      /**
       * Constructs a new ServiceOptions.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.IServiceOptions);

      /** ServiceOptions deprecated. */
      public deprecated: boolean;

      /** ServiceOptions uninterpretedOption. */
      public uninterpretedOption: google.protobuf.IUninterpretedOption[];

      /**
       * Creates a new ServiceOptions instance using the specified properties.
       * @param [properties] Properties to set
       * @returns ServiceOptions instance
       */
      public static create(properties?: google.protobuf.IServiceOptions): google.protobuf.ServiceOptions;

      /**
       * Encodes the specified ServiceOptions message. Does not implicitly {@link google.protobuf.ServiceOptions.verify|verify} messages.
       * @param m ServiceOptions message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.protobuf.IServiceOptions, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes a ServiceOptions message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns ServiceOptions
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): google.protobuf.ServiceOptions;
    }

    /** Properties of a MethodOptions. */
    interface IMethodOptions {
      /** MethodOptions deprecated */
      deprecated?: boolean | null;

      /** MethodOptions uninterpretedOption */
      uninterpretedOption?: google.protobuf.IUninterpretedOption[] | null;

      /** MethodOptions .google.api.http */
      ".google.api.http"?: google.api.IHttpRule | null;
    }

    /** Represents a MethodOptions. */
    class MethodOptions implements IMethodOptions {
      /**
       * Constructs a new MethodOptions.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.IMethodOptions);

      /** MethodOptions deprecated. */
      public deprecated: boolean;

      /** MethodOptions uninterpretedOption. */
      public uninterpretedOption: google.protobuf.IUninterpretedOption[];

      /**
       * Creates a new MethodOptions instance using the specified properties.
       * @param [properties] Properties to set
       * @returns MethodOptions instance
       */
      public static create(properties?: google.protobuf.IMethodOptions): google.protobuf.MethodOptions;

      /**
       * Encodes the specified MethodOptions message. Does not implicitly {@link google.protobuf.MethodOptions.verify|verify} messages.
       * @param m MethodOptions message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.protobuf.IMethodOptions, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes a MethodOptions message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns MethodOptions
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): google.protobuf.MethodOptions;
    }

    /** Properties of an UninterpretedOption. */
    interface IUninterpretedOption {
      /** UninterpretedOption name */
      name?: google.protobuf.UninterpretedOption.INamePart[] | null;

      /** UninterpretedOption identifierValue */
      identifierValue?: string | null;

      /** UninterpretedOption positiveIntValue */
      positiveIntValue?: Long | null;

      /** UninterpretedOption negativeIntValue */
      negativeIntValue?: Long | null;

      /** UninterpretedOption doubleValue */
      doubleValue?: number | null;

      /** UninterpretedOption stringValue */
      stringValue?: Uint8Array | null;

      /** UninterpretedOption aggregateValue */
      aggregateValue?: string | null;
    }

    /** Represents an UninterpretedOption. */
    class UninterpretedOption implements IUninterpretedOption {
      /**
       * Constructs a new UninterpretedOption.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.IUninterpretedOption);

      /** UninterpretedOption name. */
      public name: google.protobuf.UninterpretedOption.INamePart[];

      /** UninterpretedOption identifierValue. */
      public identifierValue: string;

      /** UninterpretedOption positiveIntValue. */
      public positiveIntValue: Long;

      /** UninterpretedOption negativeIntValue. */
      public negativeIntValue: Long;

      /** UninterpretedOption doubleValue. */
      public doubleValue: number;

      /** UninterpretedOption stringValue. */
      public stringValue: Uint8Array;

      /** UninterpretedOption aggregateValue. */
      public aggregateValue: string;

      /**
       * Creates a new UninterpretedOption instance using the specified properties.
       * @param [properties] Properties to set
       * @returns UninterpretedOption instance
       */
      public static create(
        properties?: google.protobuf.IUninterpretedOption,
      ): google.protobuf.UninterpretedOption;

      /**
       * Encodes the specified UninterpretedOption message. Does not implicitly {@link google.protobuf.UninterpretedOption.verify|verify} messages.
       * @param m UninterpretedOption message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.protobuf.IUninterpretedOption, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes an UninterpretedOption message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns UninterpretedOption
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): google.protobuf.UninterpretedOption;
    }

    namespace UninterpretedOption {
      /** Properties of a NamePart. */
      interface INamePart {
        /** NamePart namePart */
        namePart: string;

        /** NamePart isExtension */
        isExtension: boolean;
      }

      /** Represents a NamePart. */
      class NamePart implements INamePart {
        /**
         * Constructs a new NamePart.
         * @param [p] Properties to set
         */
        constructor(p?: google.protobuf.UninterpretedOption.INamePart);

        /** NamePart namePart. */
        public namePart: string;

        /** NamePart isExtension. */
        public isExtension: boolean;

        /**
         * Creates a new NamePart instance using the specified properties.
         * @param [properties] Properties to set
         * @returns NamePart instance
         */
        public static create(
          properties?: google.protobuf.UninterpretedOption.INamePart,
        ): google.protobuf.UninterpretedOption.NamePart;

        /**
         * Encodes the specified NamePart message. Does not implicitly {@link google.protobuf.UninterpretedOption.NamePart.verify|verify} messages.
         * @param m NamePart message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(
          m: google.protobuf.UninterpretedOption.INamePart,
          w?: $protobuf.Writer,
        ): $protobuf.Writer;

        /**
         * Decodes a NamePart message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns NamePart
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(
          r: $protobuf.Reader | Uint8Array,
          l?: number,
        ): google.protobuf.UninterpretedOption.NamePart;
      }
    }

    /** Properties of a SourceCodeInfo. */
    interface ISourceCodeInfo {
      /** SourceCodeInfo location */
      location?: google.protobuf.SourceCodeInfo.ILocation[] | null;
    }

    /** Represents a SourceCodeInfo. */
    class SourceCodeInfo implements ISourceCodeInfo {
      /**
       * Constructs a new SourceCodeInfo.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.ISourceCodeInfo);

      /** SourceCodeInfo location. */
      public location: google.protobuf.SourceCodeInfo.ILocation[];

      /**
       * Creates a new SourceCodeInfo instance using the specified properties.
       * @param [properties] Properties to set
       * @returns SourceCodeInfo instance
       */
      public static create(properties?: google.protobuf.ISourceCodeInfo): google.protobuf.SourceCodeInfo;

      /**
       * Encodes the specified SourceCodeInfo message. Does not implicitly {@link google.protobuf.SourceCodeInfo.verify|verify} messages.
       * @param m SourceCodeInfo message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.protobuf.ISourceCodeInfo, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes a SourceCodeInfo message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns SourceCodeInfo
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): google.protobuf.SourceCodeInfo;
    }

    namespace SourceCodeInfo {
      /** Properties of a Location. */
      interface ILocation {
        /** Location path */
        path?: number[] | null;

        /** Location span */
        span?: number[] | null;

        /** Location leadingComments */
        leadingComments?: string | null;

        /** Location trailingComments */
        trailingComments?: string | null;

        /** Location leadingDetachedComments */
        leadingDetachedComments?: string[] | null;
      }

      /** Represents a Location. */
      class Location implements ILocation {
        /**
         * Constructs a new Location.
         * @param [p] Properties to set
         */
        constructor(p?: google.protobuf.SourceCodeInfo.ILocation);

        /** Location path. */
        public path: number[];

        /** Location span. */
        public span: number[];

        /** Location leadingComments. */
        public leadingComments: string;

        /** Location trailingComments. */
        public trailingComments: string;

        /** Location leadingDetachedComments. */
        public leadingDetachedComments: string[];

        /**
         * Creates a new Location instance using the specified properties.
         * @param [properties] Properties to set
         * @returns Location instance
         */
        public static create(
          properties?: google.protobuf.SourceCodeInfo.ILocation,
        ): google.protobuf.SourceCodeInfo.Location;

        /**
         * Encodes the specified Location message. Does not implicitly {@link google.protobuf.SourceCodeInfo.Location.verify|verify} messages.
         * @param m Location message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(
          m: google.protobuf.SourceCodeInfo.ILocation,
          w?: $protobuf.Writer,
        ): $protobuf.Writer;

        /**
         * Decodes a Location message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns Location
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(
          r: $protobuf.Reader | Uint8Array,
          l?: number,
        ): google.protobuf.SourceCodeInfo.Location;
      }
    }

    /** Properties of a GeneratedCodeInfo. */
    interface IGeneratedCodeInfo {
      /** GeneratedCodeInfo annotation */
      annotation?: google.protobuf.GeneratedCodeInfo.IAnnotation[] | null;
    }

    /** Represents a GeneratedCodeInfo. */
    class GeneratedCodeInfo implements IGeneratedCodeInfo {
      /**
       * Constructs a new GeneratedCodeInfo.
       * @param [p] Properties to set
       */
      constructor(p?: google.protobuf.IGeneratedCodeInfo);

      /** GeneratedCodeInfo annotation. */
      public annotation: google.protobuf.GeneratedCodeInfo.IAnnotation[];

      /**
       * Creates a new GeneratedCodeInfo instance using the specified properties.
       * @param [properties] Properties to set
       * @returns GeneratedCodeInfo instance
       */
      public static create(
        properties?: google.protobuf.IGeneratedCodeInfo,
      ): google.protobuf.GeneratedCodeInfo;

      /**
       * Encodes the specified GeneratedCodeInfo message. Does not implicitly {@link google.protobuf.GeneratedCodeInfo.verify|verify} messages.
       * @param m GeneratedCodeInfo message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.protobuf.IGeneratedCodeInfo, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes a GeneratedCodeInfo message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns GeneratedCodeInfo
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): google.protobuf.GeneratedCodeInfo;
    }

    namespace GeneratedCodeInfo {
      /** Properties of an Annotation. */
      interface IAnnotation {
        /** Annotation path */
        path?: number[] | null;

        /** Annotation sourceFile */
        sourceFile?: string | null;

        /** Annotation begin */
        begin?: number | null;

        /** Annotation end */
        end?: number | null;
      }

      /** Represents an Annotation. */
      class Annotation implements IAnnotation {
        /**
         * Constructs a new Annotation.
         * @param [p] Properties to set
         */
        constructor(p?: google.protobuf.GeneratedCodeInfo.IAnnotation);

        /** Annotation path. */
        public path: number[];

        /** Annotation sourceFile. */
        public sourceFile: string;

        /** Annotation begin. */
        public begin: number;

        /** Annotation end. */
        public end: number;

        /**
         * Creates a new Annotation instance using the specified properties.
         * @param [properties] Properties to set
         * @returns Annotation instance
         */
        public static create(
          properties?: google.protobuf.GeneratedCodeInfo.IAnnotation,
        ): google.protobuf.GeneratedCodeInfo.Annotation;

        /**
         * Encodes the specified Annotation message. Does not implicitly {@link google.protobuf.GeneratedCodeInfo.Annotation.verify|verify} messages.
         * @param m Annotation message or plain object to encode
         * @param [w] Writer to encode to
         * @returns Writer
         */
        public static encode(
          m: google.protobuf.GeneratedCodeInfo.IAnnotation,
          w?: $protobuf.Writer,
        ): $protobuf.Writer;

        /**
         * Decodes an Annotation message from the specified reader or buffer.
         * @param r Reader or buffer to decode from
         * @param [l] Message length if known beforehand
         * @returns Annotation
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(
          r: $protobuf.Reader | Uint8Array,
          l?: number,
        ): google.protobuf.GeneratedCodeInfo.Annotation;
      }
    }
  }

  /** Namespace api. */
  namespace api {
    /** Properties of a Http. */
    interface IHttp {
      /** Http rules */
      rules?: google.api.IHttpRule[] | null;
    }

    /** Represents a Http. */
    class Http implements IHttp {
      /**
       * Constructs a new Http.
       * @param [p] Properties to set
       */
      constructor(p?: google.api.IHttp);

      /** Http rules. */
      public rules: google.api.IHttpRule[];

      /**
       * Creates a new Http instance using the specified properties.
       * @param [properties] Properties to set
       * @returns Http instance
       */
      public static create(properties?: google.api.IHttp): google.api.Http;

      /**
       * Encodes the specified Http message. Does not implicitly {@link google.api.Http.verify|verify} messages.
       * @param m Http message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.api.IHttp, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes a Http message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns Http
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): google.api.Http;
    }

    /** Properties of a HttpRule. */
    interface IHttpRule {
      /** HttpRule get */
      get?: string | null;

      /** HttpRule put */
      put?: string | null;

      /** HttpRule post */
      post?: string | null;

      /** HttpRule delete */
      delete?: string | null;

      /** HttpRule patch */
      patch?: string | null;

      /** HttpRule custom */
      custom?: google.api.ICustomHttpPattern | null;

      /** HttpRule selector */
      selector?: string | null;

      /** HttpRule body */
      body?: string | null;

      /** HttpRule additionalBindings */
      additionalBindings?: google.api.IHttpRule[] | null;
    }

    /** Represents a HttpRule. */
    class HttpRule implements IHttpRule {
      /**
       * Constructs a new HttpRule.
       * @param [p] Properties to set
       */
      constructor(p?: google.api.IHttpRule);

      /** HttpRule get. */
      public get: string;

      /** HttpRule put. */
      public put: string;

      /** HttpRule post. */
      public post: string;

      /** HttpRule delete. */
      public delete: string;

      /** HttpRule patch. */
      public patch: string;

      /** HttpRule custom. */
      public custom?: google.api.ICustomHttpPattern | null;

      /** HttpRule selector. */
      public selector: string;

      /** HttpRule body. */
      public body: string;

      /** HttpRule additionalBindings. */
      public additionalBindings: google.api.IHttpRule[];

      /** HttpRule pattern. */
      public pattern?: "get" | "put" | "post" | "delete" | "patch" | "custom";

      /**
       * Creates a new HttpRule instance using the specified properties.
       * @param [properties] Properties to set
       * @returns HttpRule instance
       */
      public static create(properties?: google.api.IHttpRule): google.api.HttpRule;

      /**
       * Encodes the specified HttpRule message. Does not implicitly {@link google.api.HttpRule.verify|verify} messages.
       * @param m HttpRule message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.api.IHttpRule, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes a HttpRule message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns HttpRule
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): google.api.HttpRule;
    }

    /** Properties of a CustomHttpPattern. */
    interface ICustomHttpPattern {
      /** CustomHttpPattern kind */
      kind?: string | null;

      /** CustomHttpPattern path */
      path?: string | null;
    }

    /** Represents a CustomHttpPattern. */
    class CustomHttpPattern implements ICustomHttpPattern {
      /**
       * Constructs a new CustomHttpPattern.
       * @param [p] Properties to set
       */
      constructor(p?: google.api.ICustomHttpPattern);

      /** CustomHttpPattern kind. */
      public kind: string;

      /** CustomHttpPattern path. */
      public path: string;

      /**
       * Creates a new CustomHttpPattern instance using the specified properties.
       * @param [properties] Properties to set
       * @returns CustomHttpPattern instance
       */
      public static create(properties?: google.api.ICustomHttpPattern): google.api.CustomHttpPattern;

      /**
       * Encodes the specified CustomHttpPattern message. Does not implicitly {@link google.api.CustomHttpPattern.verify|verify} messages.
       * @param m CustomHttpPattern message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: google.api.ICustomHttpPattern, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes a CustomHttpPattern message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns CustomHttpPattern
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): google.api.CustomHttpPattern;
    }
  }
}

/** Namespace ibc. */
export namespace ibc {
  /** Namespace core. */
  namespace core {
    /** Namespace channel. */
    namespace channel {
      /** Namespace v1. */
      namespace v1 {
        /** Properties of a MsgChannelOpenInit. */
        interface IMsgChannelOpenInit {
          /** MsgChannelOpenInit portId */
          portId?: string | null;

          /** MsgChannelOpenInit channelId */
          channelId?: string | null;

          /** MsgChannelOpenInit channel */
          channel?: ibc.core.channel.v1.IChannel | null;

          /** MsgChannelOpenInit signer */
          signer?: string | null;
        }

        /** Represents a MsgChannelOpenInit. */
        class MsgChannelOpenInit implements IMsgChannelOpenInit {
          /**
           * Constructs a new MsgChannelOpenInit.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IMsgChannelOpenInit);

          /** MsgChannelOpenInit portId. */
          public portId: string;

          /** MsgChannelOpenInit channelId. */
          public channelId: string;

          /** MsgChannelOpenInit channel. */
          public channel?: ibc.core.channel.v1.IChannel | null;

          /** MsgChannelOpenInit signer. */
          public signer: string;

          /**
           * Creates a new MsgChannelOpenInit instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MsgChannelOpenInit instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IMsgChannelOpenInit,
          ): ibc.core.channel.v1.MsgChannelOpenInit;

          /**
           * Encodes the specified MsgChannelOpenInit message. Does not implicitly {@link ibc.core.channel.v1.MsgChannelOpenInit.verify|verify} messages.
           * @param m MsgChannelOpenInit message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IMsgChannelOpenInit,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a MsgChannelOpenInit message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MsgChannelOpenInit
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.MsgChannelOpenInit;
        }

        /** Properties of a MsgChannelOpenTry. */
        interface IMsgChannelOpenTry {
          /** MsgChannelOpenTry portId */
          portId?: string | null;

          /** MsgChannelOpenTry channelId */
          channelId?: string | null;

          /** MsgChannelOpenTry channel */
          channel?: ibc.core.channel.v1.IChannel | null;

          /** MsgChannelOpenTry counterpartyVersion */
          counterpartyVersion?: string | null;

          /** MsgChannelOpenTry proofInit */
          proofInit?: Uint8Array | null;

          /** MsgChannelOpenTry proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgChannelOpenTry signer */
          signer?: string | null;
        }

        /** Represents a MsgChannelOpenTry. */
        class MsgChannelOpenTry implements IMsgChannelOpenTry {
          /**
           * Constructs a new MsgChannelOpenTry.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IMsgChannelOpenTry);

          /** MsgChannelOpenTry portId. */
          public portId: string;

          /** MsgChannelOpenTry channelId. */
          public channelId: string;

          /** MsgChannelOpenTry channel. */
          public channel?: ibc.core.channel.v1.IChannel | null;

          /** MsgChannelOpenTry counterpartyVersion. */
          public counterpartyVersion: string;

          /** MsgChannelOpenTry proofInit. */
          public proofInit: Uint8Array;

          /** MsgChannelOpenTry proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgChannelOpenTry signer. */
          public signer: string;

          /**
           * Creates a new MsgChannelOpenTry instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MsgChannelOpenTry instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IMsgChannelOpenTry,
          ): ibc.core.channel.v1.MsgChannelOpenTry;

          /**
           * Encodes the specified MsgChannelOpenTry message. Does not implicitly {@link ibc.core.channel.v1.MsgChannelOpenTry.verify|verify} messages.
           * @param m MsgChannelOpenTry message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IMsgChannelOpenTry,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a MsgChannelOpenTry message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MsgChannelOpenTry
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.MsgChannelOpenTry;
        }

        /** Properties of a MsgChannelOpenAck. */
        interface IMsgChannelOpenAck {
          /** MsgChannelOpenAck portId */
          portId?: string | null;

          /** MsgChannelOpenAck channelId */
          channelId?: string | null;

          /** MsgChannelOpenAck counterpartyVersion */
          counterpartyVersion?: string | null;

          /** MsgChannelOpenAck proofTry */
          proofTry?: Uint8Array | null;

          /** MsgChannelOpenAck proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgChannelOpenAck signer */
          signer?: string | null;
        }

        /** Represents a MsgChannelOpenAck. */
        class MsgChannelOpenAck implements IMsgChannelOpenAck {
          /**
           * Constructs a new MsgChannelOpenAck.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IMsgChannelOpenAck);

          /** MsgChannelOpenAck portId. */
          public portId: string;

          /** MsgChannelOpenAck channelId. */
          public channelId: string;

          /** MsgChannelOpenAck counterpartyVersion. */
          public counterpartyVersion: string;

          /** MsgChannelOpenAck proofTry. */
          public proofTry: Uint8Array;

          /** MsgChannelOpenAck proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgChannelOpenAck signer. */
          public signer: string;

          /**
           * Creates a new MsgChannelOpenAck instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MsgChannelOpenAck instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IMsgChannelOpenAck,
          ): ibc.core.channel.v1.MsgChannelOpenAck;

          /**
           * Encodes the specified MsgChannelOpenAck message. Does not implicitly {@link ibc.core.channel.v1.MsgChannelOpenAck.verify|verify} messages.
           * @param m MsgChannelOpenAck message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IMsgChannelOpenAck,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a MsgChannelOpenAck message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MsgChannelOpenAck
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.MsgChannelOpenAck;
        }

        /** Properties of a MsgChannelOpenConfirm. */
        interface IMsgChannelOpenConfirm {
          /** MsgChannelOpenConfirm portId */
          portId?: string | null;

          /** MsgChannelOpenConfirm channelId */
          channelId?: string | null;

          /** MsgChannelOpenConfirm proofAck */
          proofAck?: Uint8Array | null;

          /** MsgChannelOpenConfirm proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgChannelOpenConfirm signer */
          signer?: string | null;
        }

        /** Represents a MsgChannelOpenConfirm. */
        class MsgChannelOpenConfirm implements IMsgChannelOpenConfirm {
          /**
           * Constructs a new MsgChannelOpenConfirm.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IMsgChannelOpenConfirm);

          /** MsgChannelOpenConfirm portId. */
          public portId: string;

          /** MsgChannelOpenConfirm channelId. */
          public channelId: string;

          /** MsgChannelOpenConfirm proofAck. */
          public proofAck: Uint8Array;

          /** MsgChannelOpenConfirm proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgChannelOpenConfirm signer. */
          public signer: string;

          /**
           * Creates a new MsgChannelOpenConfirm instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MsgChannelOpenConfirm instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IMsgChannelOpenConfirm,
          ): ibc.core.channel.v1.MsgChannelOpenConfirm;

          /**
           * Encodes the specified MsgChannelOpenConfirm message. Does not implicitly {@link ibc.core.channel.v1.MsgChannelOpenConfirm.verify|verify} messages.
           * @param m MsgChannelOpenConfirm message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IMsgChannelOpenConfirm,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a MsgChannelOpenConfirm message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MsgChannelOpenConfirm
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.MsgChannelOpenConfirm;
        }

        /** Properties of a MsgChannelCloseInit. */
        interface IMsgChannelCloseInit {
          /** MsgChannelCloseInit portId */
          portId?: string | null;

          /** MsgChannelCloseInit channelId */
          channelId?: string | null;

          /** MsgChannelCloseInit signer */
          signer?: string | null;
        }

        /** Represents a MsgChannelCloseInit. */
        class MsgChannelCloseInit implements IMsgChannelCloseInit {
          /**
           * Constructs a new MsgChannelCloseInit.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IMsgChannelCloseInit);

          /** MsgChannelCloseInit portId. */
          public portId: string;

          /** MsgChannelCloseInit channelId. */
          public channelId: string;

          /** MsgChannelCloseInit signer. */
          public signer: string;

          /**
           * Creates a new MsgChannelCloseInit instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MsgChannelCloseInit instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IMsgChannelCloseInit,
          ): ibc.core.channel.v1.MsgChannelCloseInit;

          /**
           * Encodes the specified MsgChannelCloseInit message. Does not implicitly {@link ibc.core.channel.v1.MsgChannelCloseInit.verify|verify} messages.
           * @param m MsgChannelCloseInit message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IMsgChannelCloseInit,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a MsgChannelCloseInit message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MsgChannelCloseInit
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.MsgChannelCloseInit;
        }

        /** Properties of a MsgChannelCloseConfirm. */
        interface IMsgChannelCloseConfirm {
          /** MsgChannelCloseConfirm portId */
          portId?: string | null;

          /** MsgChannelCloseConfirm channelId */
          channelId?: string | null;

          /** MsgChannelCloseConfirm proofInit */
          proofInit?: Uint8Array | null;

          /** MsgChannelCloseConfirm proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgChannelCloseConfirm signer */
          signer?: string | null;
        }

        /** Represents a MsgChannelCloseConfirm. */
        class MsgChannelCloseConfirm implements IMsgChannelCloseConfirm {
          /**
           * Constructs a new MsgChannelCloseConfirm.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IMsgChannelCloseConfirm);

          /** MsgChannelCloseConfirm portId. */
          public portId: string;

          /** MsgChannelCloseConfirm channelId. */
          public channelId: string;

          /** MsgChannelCloseConfirm proofInit. */
          public proofInit: Uint8Array;

          /** MsgChannelCloseConfirm proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgChannelCloseConfirm signer. */
          public signer: string;

          /**
           * Creates a new MsgChannelCloseConfirm instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MsgChannelCloseConfirm instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IMsgChannelCloseConfirm,
          ): ibc.core.channel.v1.MsgChannelCloseConfirm;

          /**
           * Encodes the specified MsgChannelCloseConfirm message. Does not implicitly {@link ibc.core.channel.v1.MsgChannelCloseConfirm.verify|verify} messages.
           * @param m MsgChannelCloseConfirm message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IMsgChannelCloseConfirm,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a MsgChannelCloseConfirm message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MsgChannelCloseConfirm
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.MsgChannelCloseConfirm;
        }

        /** Properties of a MsgRecvPacket. */
        interface IMsgRecvPacket {
          /** MsgRecvPacket packet */
          packet?: ibc.core.channel.v1.IPacket | null;

          /** MsgRecvPacket proof */
          proof?: Uint8Array | null;

          /** MsgRecvPacket proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgRecvPacket signer */
          signer?: string | null;
        }

        /** Represents a MsgRecvPacket. */
        class MsgRecvPacket implements IMsgRecvPacket {
          /**
           * Constructs a new MsgRecvPacket.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IMsgRecvPacket);

          /** MsgRecvPacket packet. */
          public packet?: ibc.core.channel.v1.IPacket | null;

          /** MsgRecvPacket proof. */
          public proof: Uint8Array;

          /** MsgRecvPacket proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgRecvPacket signer. */
          public signer: string;

          /**
           * Creates a new MsgRecvPacket instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MsgRecvPacket instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IMsgRecvPacket,
          ): ibc.core.channel.v1.MsgRecvPacket;

          /**
           * Encodes the specified MsgRecvPacket message. Does not implicitly {@link ibc.core.channel.v1.MsgRecvPacket.verify|verify} messages.
           * @param m MsgRecvPacket message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(m: ibc.core.channel.v1.IMsgRecvPacket, w?: $protobuf.Writer): $protobuf.Writer;

          /**
           * Decodes a MsgRecvPacket message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MsgRecvPacket
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.MsgRecvPacket;
        }

        /** Properties of a MsgTimeout. */
        interface IMsgTimeout {
          /** MsgTimeout packet */
          packet?: ibc.core.channel.v1.IPacket | null;

          /** MsgTimeout proof */
          proof?: Uint8Array | null;

          /** MsgTimeout proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgTimeout nextSequenceRecv */
          nextSequenceRecv?: Long | null;

          /** MsgTimeout signer */
          signer?: string | null;
        }

        /** Represents a MsgTimeout. */
        class MsgTimeout implements IMsgTimeout {
          /**
           * Constructs a new MsgTimeout.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IMsgTimeout);

          /** MsgTimeout packet. */
          public packet?: ibc.core.channel.v1.IPacket | null;

          /** MsgTimeout proof. */
          public proof: Uint8Array;

          /** MsgTimeout proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgTimeout nextSequenceRecv. */
          public nextSequenceRecv: Long;

          /** MsgTimeout signer. */
          public signer: string;

          /**
           * Creates a new MsgTimeout instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MsgTimeout instance
           */
          public static create(properties?: ibc.core.channel.v1.IMsgTimeout): ibc.core.channel.v1.MsgTimeout;

          /**
           * Encodes the specified MsgTimeout message. Does not implicitly {@link ibc.core.channel.v1.MsgTimeout.verify|verify} messages.
           * @param m MsgTimeout message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(m: ibc.core.channel.v1.IMsgTimeout, w?: $protobuf.Writer): $protobuf.Writer;

          /**
           * Decodes a MsgTimeout message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MsgTimeout
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(r: $protobuf.Reader | Uint8Array, l?: number): ibc.core.channel.v1.MsgTimeout;
        }

        /** Properties of a MsgTimeoutOnClose. */
        interface IMsgTimeoutOnClose {
          /** MsgTimeoutOnClose packet */
          packet?: ibc.core.channel.v1.IPacket | null;

          /** MsgTimeoutOnClose proof */
          proof?: Uint8Array | null;

          /** MsgTimeoutOnClose proofClose */
          proofClose?: Uint8Array | null;

          /** MsgTimeoutOnClose proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgTimeoutOnClose nextSequenceRecv */
          nextSequenceRecv?: Long | null;

          /** MsgTimeoutOnClose signer */
          signer?: string | null;
        }

        /** Represents a MsgTimeoutOnClose. */
        class MsgTimeoutOnClose implements IMsgTimeoutOnClose {
          /**
           * Constructs a new MsgTimeoutOnClose.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IMsgTimeoutOnClose);

          /** MsgTimeoutOnClose packet. */
          public packet?: ibc.core.channel.v1.IPacket | null;

          /** MsgTimeoutOnClose proof. */
          public proof: Uint8Array;

          /** MsgTimeoutOnClose proofClose. */
          public proofClose: Uint8Array;

          /** MsgTimeoutOnClose proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgTimeoutOnClose nextSequenceRecv. */
          public nextSequenceRecv: Long;

          /** MsgTimeoutOnClose signer. */
          public signer: string;

          /**
           * Creates a new MsgTimeoutOnClose instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MsgTimeoutOnClose instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IMsgTimeoutOnClose,
          ): ibc.core.channel.v1.MsgTimeoutOnClose;

          /**
           * Encodes the specified MsgTimeoutOnClose message. Does not implicitly {@link ibc.core.channel.v1.MsgTimeoutOnClose.verify|verify} messages.
           * @param m MsgTimeoutOnClose message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IMsgTimeoutOnClose,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a MsgTimeoutOnClose message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MsgTimeoutOnClose
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.MsgTimeoutOnClose;
        }

        /** Properties of a MsgAcknowledgement. */
        interface IMsgAcknowledgement {
          /** MsgAcknowledgement packet */
          packet?: ibc.core.channel.v1.IPacket | null;

          /** MsgAcknowledgement acknowledgement */
          acknowledgement?: Uint8Array | null;

          /** MsgAcknowledgement proof */
          proof?: Uint8Array | null;

          /** MsgAcknowledgement proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgAcknowledgement signer */
          signer?: string | null;
        }

        /** Represents a MsgAcknowledgement. */
        class MsgAcknowledgement implements IMsgAcknowledgement {
          /**
           * Constructs a new MsgAcknowledgement.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IMsgAcknowledgement);

          /** MsgAcknowledgement packet. */
          public packet?: ibc.core.channel.v1.IPacket | null;

          /** MsgAcknowledgement acknowledgement. */
          public acknowledgement: Uint8Array;

          /** MsgAcknowledgement proof. */
          public proof: Uint8Array;

          /** MsgAcknowledgement proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgAcknowledgement signer. */
          public signer: string;

          /**
           * Creates a new MsgAcknowledgement instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MsgAcknowledgement instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IMsgAcknowledgement,
          ): ibc.core.channel.v1.MsgAcknowledgement;

          /**
           * Encodes the specified MsgAcknowledgement message. Does not implicitly {@link ibc.core.channel.v1.MsgAcknowledgement.verify|verify} messages.
           * @param m MsgAcknowledgement message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IMsgAcknowledgement,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a MsgAcknowledgement message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MsgAcknowledgement
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.MsgAcknowledgement;
        }

        /** Properties of a Channel. */
        interface IChannel {
          /** Channel state */
          state?: ibc.core.channel.v1.State | null;

          /** Channel ordering */
          ordering?: ibc.core.channel.v1.Order | null;

          /** Channel counterparty */
          counterparty?: ibc.core.channel.v1.ICounterparty | null;

          /** Channel connectionHops */
          connectionHops?: string[] | null;

          /** Channel version */
          version?: string | null;
        }

        /** Represents a Channel. */
        class Channel implements IChannel {
          /**
           * Constructs a new Channel.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IChannel);

          /** Channel state. */
          public state: ibc.core.channel.v1.State;

          /** Channel ordering. */
          public ordering: ibc.core.channel.v1.Order;

          /** Channel counterparty. */
          public counterparty?: ibc.core.channel.v1.ICounterparty | null;

          /** Channel connectionHops. */
          public connectionHops: string[];

          /** Channel version. */
          public version: string;

          /**
           * Creates a new Channel instance using the specified properties.
           * @param [properties] Properties to set
           * @returns Channel instance
           */
          public static create(properties?: ibc.core.channel.v1.IChannel): ibc.core.channel.v1.Channel;

          /**
           * Encodes the specified Channel message. Does not implicitly {@link ibc.core.channel.v1.Channel.verify|verify} messages.
           * @param m Channel message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(m: ibc.core.channel.v1.IChannel, w?: $protobuf.Writer): $protobuf.Writer;

          /**
           * Decodes a Channel message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns Channel
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(r: $protobuf.Reader | Uint8Array, l?: number): ibc.core.channel.v1.Channel;
        }

        /** Properties of an IdentifiedChannel. */
        interface IIdentifiedChannel {
          /** IdentifiedChannel state */
          state?: ibc.core.channel.v1.State | null;

          /** IdentifiedChannel ordering */
          ordering?: ibc.core.channel.v1.Order | null;

          /** IdentifiedChannel counterparty */
          counterparty?: ibc.core.channel.v1.ICounterparty | null;

          /** IdentifiedChannel connectionHops */
          connectionHops?: string[] | null;

          /** IdentifiedChannel version */
          version?: string | null;

          /** IdentifiedChannel portId */
          portId?: string | null;

          /** IdentifiedChannel channelId */
          channelId?: string | null;
        }

        /** Represents an IdentifiedChannel. */
        class IdentifiedChannel implements IIdentifiedChannel {
          /**
           * Constructs a new IdentifiedChannel.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IIdentifiedChannel);

          /** IdentifiedChannel state. */
          public state: ibc.core.channel.v1.State;

          /** IdentifiedChannel ordering. */
          public ordering: ibc.core.channel.v1.Order;

          /** IdentifiedChannel counterparty. */
          public counterparty?: ibc.core.channel.v1.ICounterparty | null;

          /** IdentifiedChannel connectionHops. */
          public connectionHops: string[];

          /** IdentifiedChannel version. */
          public version: string;

          /** IdentifiedChannel portId. */
          public portId: string;

          /** IdentifiedChannel channelId. */
          public channelId: string;

          /**
           * Creates a new IdentifiedChannel instance using the specified properties.
           * @param [properties] Properties to set
           * @returns IdentifiedChannel instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IIdentifiedChannel,
          ): ibc.core.channel.v1.IdentifiedChannel;

          /**
           * Encodes the specified IdentifiedChannel message. Does not implicitly {@link ibc.core.channel.v1.IdentifiedChannel.verify|verify} messages.
           * @param m IdentifiedChannel message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IIdentifiedChannel,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes an IdentifiedChannel message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns IdentifiedChannel
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.IdentifiedChannel;
        }

        /** State enum. */
        enum State {
          STATE_UNINITIALIZED_UNSPECIFIED = 0,
          STATE_INIT = 1,
          STATE_TRYOPEN = 2,
          STATE_OPEN = 3,
          STATE_CLOSED = 4,
        }

        /** Order enum. */
        enum Order {
          ORDER_NONE_UNSPECIFIED = 0,
          ORDER_UNORDERED = 1,
          ORDER_ORDERED = 2,
        }

        /** Properties of a Counterparty. */
        interface ICounterparty {
          /** Counterparty portId */
          portId?: string | null;

          /** Counterparty channelId */
          channelId?: string | null;
        }

        /** Represents a Counterparty. */
        class Counterparty implements ICounterparty {
          /**
           * Constructs a new Counterparty.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.ICounterparty);

          /** Counterparty portId. */
          public portId: string;

          /** Counterparty channelId. */
          public channelId: string;

          /**
           * Creates a new Counterparty instance using the specified properties.
           * @param [properties] Properties to set
           * @returns Counterparty instance
           */
          public static create(
            properties?: ibc.core.channel.v1.ICounterparty,
          ): ibc.core.channel.v1.Counterparty;

          /**
           * Encodes the specified Counterparty message. Does not implicitly {@link ibc.core.channel.v1.Counterparty.verify|verify} messages.
           * @param m Counterparty message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(m: ibc.core.channel.v1.ICounterparty, w?: $protobuf.Writer): $protobuf.Writer;

          /**
           * Decodes a Counterparty message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns Counterparty
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.Counterparty;
        }

        /** Properties of a Packet. */
        interface IPacket {
          /** Packet sequence */
          sequence?: Long | null;

          /** Packet sourcePort */
          sourcePort?: string | null;

          /** Packet sourceChannel */
          sourceChannel?: string | null;

          /** Packet destinationPort */
          destinationPort?: string | null;

          /** Packet destinationChannel */
          destinationChannel?: string | null;

          /** Packet data */
          data?: Uint8Array | null;

          /** Packet timeoutHeight */
          timeoutHeight?: ibc.core.client.v1.IHeight | null;

          /** Packet timeoutTimestamp */
          timeoutTimestamp?: Long | null;
        }

        /** Represents a Packet. */
        class Packet implements IPacket {
          /**
           * Constructs a new Packet.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IPacket);

          /** Packet sequence. */
          public sequence: Long;

          /** Packet sourcePort. */
          public sourcePort: string;

          /** Packet sourceChannel. */
          public sourceChannel: string;

          /** Packet destinationPort. */
          public destinationPort: string;

          /** Packet destinationChannel. */
          public destinationChannel: string;

          /** Packet data. */
          public data: Uint8Array;

          /** Packet timeoutHeight. */
          public timeoutHeight?: ibc.core.client.v1.IHeight | null;

          /** Packet timeoutTimestamp. */
          public timeoutTimestamp: Long;

          /**
           * Creates a new Packet instance using the specified properties.
           * @param [properties] Properties to set
           * @returns Packet instance
           */
          public static create(properties?: ibc.core.channel.v1.IPacket): ibc.core.channel.v1.Packet;

          /**
           * Encodes the specified Packet message. Does not implicitly {@link ibc.core.channel.v1.Packet.verify|verify} messages.
           * @param m Packet message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(m: ibc.core.channel.v1.IPacket, w?: $protobuf.Writer): $protobuf.Writer;

          /**
           * Decodes a Packet message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns Packet
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(r: $protobuf.Reader | Uint8Array, l?: number): ibc.core.channel.v1.Packet;
        }

        /** Properties of a PacketAckCommitment. */
        interface IPacketAckCommitment {
          /** PacketAckCommitment portId */
          portId?: string | null;

          /** PacketAckCommitment channelId */
          channelId?: string | null;

          /** PacketAckCommitment sequence */
          sequence?: Long | null;

          /** PacketAckCommitment hash */
          hash?: Uint8Array | null;
        }

        /** Represents a PacketAckCommitment. */
        class PacketAckCommitment implements IPacketAckCommitment {
          /**
           * Constructs a new PacketAckCommitment.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IPacketAckCommitment);

          /** PacketAckCommitment portId. */
          public portId: string;

          /** PacketAckCommitment channelId. */
          public channelId: string;

          /** PacketAckCommitment sequence. */
          public sequence: Long;

          /** PacketAckCommitment hash. */
          public hash: Uint8Array;

          /**
           * Creates a new PacketAckCommitment instance using the specified properties.
           * @param [properties] Properties to set
           * @returns PacketAckCommitment instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IPacketAckCommitment,
          ): ibc.core.channel.v1.PacketAckCommitment;

          /**
           * Encodes the specified PacketAckCommitment message. Does not implicitly {@link ibc.core.channel.v1.PacketAckCommitment.verify|verify} messages.
           * @param m PacketAckCommitment message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IPacketAckCommitment,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a PacketAckCommitment message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns PacketAckCommitment
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.PacketAckCommitment;
        }

        /** Properties of an Acknowledgement. */
        interface IAcknowledgement {
          /** Acknowledgement result */
          result?: Uint8Array | null;

          /** Acknowledgement error */
          error?: string | null;
        }

        /** Represents an Acknowledgement. */
        class Acknowledgement implements IAcknowledgement {
          /**
           * Constructs a new Acknowledgement.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IAcknowledgement);

          /** Acknowledgement result. */
          public result: Uint8Array;

          /** Acknowledgement error. */
          public error: string;

          /** Acknowledgement response. */
          public response?: "result" | "error";

          /**
           * Creates a new Acknowledgement instance using the specified properties.
           * @param [properties] Properties to set
           * @returns Acknowledgement instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IAcknowledgement,
          ): ibc.core.channel.v1.Acknowledgement;

          /**
           * Encodes the specified Acknowledgement message. Does not implicitly {@link ibc.core.channel.v1.Acknowledgement.verify|verify} messages.
           * @param m Acknowledgement message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IAcknowledgement,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes an Acknowledgement message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns Acknowledgement
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.Acknowledgement;
        }

        /** Represents a Query */
        class Query extends $protobuf.rpc.Service {
          /**
           * Constructs a new Query service.
           * @param rpcImpl RPC implementation
           * @param [requestDelimited=false] Whether requests are length-delimited
           * @param [responseDelimited=false] Whether responses are length-delimited
           */
          constructor(rpcImpl: $protobuf.RPCImpl, requestDelimited?: boolean, responseDelimited?: boolean);

          /**
           * Creates new Query service using the specified rpc implementation.
           * @param rpcImpl RPC implementation
           * @param [requestDelimited=false] Whether requests are length-delimited
           * @param [responseDelimited=false] Whether responses are length-delimited
           * @returns RPC service. Useful where requests and/or responses are streamed.
           */
          public static create(
            rpcImpl: $protobuf.RPCImpl,
            requestDelimited?: boolean,
            responseDelimited?: boolean,
          ): Query;

          /**
           * Calls Channel.
           * @param request QueryChannelRequest message or plain object
           * @param callback Node-style callback called with the error, if any, and QueryChannelResponse
           */
          public channel(
            request: ibc.core.channel.v1.IQueryChannelRequest,
            callback: ibc.core.channel.v1.Query.ChannelCallback,
          ): void;

          /**
           * Calls Channel.
           * @param request QueryChannelRequest message or plain object
           * @returns Promise
           */
          public channel(
            request: ibc.core.channel.v1.IQueryChannelRequest,
          ): Promise<ibc.core.channel.v1.QueryChannelResponse>;

          /**
           * Calls Channels.
           * @param request QueryChannelsRequest message or plain object
           * @param callback Node-style callback called with the error, if any, and QueryChannelsResponse
           */
          public channels(
            request: ibc.core.channel.v1.IQueryChannelsRequest,
            callback: ibc.core.channel.v1.Query.ChannelsCallback,
          ): void;

          /**
           * Calls Channels.
           * @param request QueryChannelsRequest message or plain object
           * @returns Promise
           */
          public channels(
            request: ibc.core.channel.v1.IQueryChannelsRequest,
          ): Promise<ibc.core.channel.v1.QueryChannelsResponse>;

          /**
           * Calls ConnectionChannels.
           * @param request QueryConnectionChannelsRequest message or plain object
           * @param callback Node-style callback called with the error, if any, and QueryConnectionChannelsResponse
           */
          public connectionChannels(
            request: ibc.core.channel.v1.IQueryConnectionChannelsRequest,
            callback: ibc.core.channel.v1.Query.ConnectionChannelsCallback,
          ): void;

          /**
           * Calls ConnectionChannels.
           * @param request QueryConnectionChannelsRequest message or plain object
           * @returns Promise
           */
          public connectionChannels(
            request: ibc.core.channel.v1.IQueryConnectionChannelsRequest,
          ): Promise<ibc.core.channel.v1.QueryConnectionChannelsResponse>;

          /**
           * Calls ChannelClientState.
           * @param request QueryChannelClientStateRequest message or plain object
           * @param callback Node-style callback called with the error, if any, and QueryChannelClientStateResponse
           */
          public channelClientState(
            request: ibc.core.channel.v1.IQueryChannelClientStateRequest,
            callback: ibc.core.channel.v1.Query.ChannelClientStateCallback,
          ): void;

          /**
           * Calls ChannelClientState.
           * @param request QueryChannelClientStateRequest message or plain object
           * @returns Promise
           */
          public channelClientState(
            request: ibc.core.channel.v1.IQueryChannelClientStateRequest,
          ): Promise<ibc.core.channel.v1.QueryChannelClientStateResponse>;

          /**
           * Calls ChannelConsensusState.
           * @param request QueryChannelConsensusStateRequest message or plain object
           * @param callback Node-style callback called with the error, if any, and QueryChannelConsensusStateResponse
           */
          public channelConsensusState(
            request: ibc.core.channel.v1.IQueryChannelConsensusStateRequest,
            callback: ibc.core.channel.v1.Query.ChannelConsensusStateCallback,
          ): void;

          /**
           * Calls ChannelConsensusState.
           * @param request QueryChannelConsensusStateRequest message or plain object
           * @returns Promise
           */
          public channelConsensusState(
            request: ibc.core.channel.v1.IQueryChannelConsensusStateRequest,
          ): Promise<ibc.core.channel.v1.QueryChannelConsensusStateResponse>;

          /**
           * Calls PacketCommitment.
           * @param request QueryPacketCommitmentRequest message or plain object
           * @param callback Node-style callback called with the error, if any, and QueryPacketCommitmentResponse
           */
          public packetCommitment(
            request: ibc.core.channel.v1.IQueryPacketCommitmentRequest,
            callback: ibc.core.channel.v1.Query.PacketCommitmentCallback,
          ): void;

          /**
           * Calls PacketCommitment.
           * @param request QueryPacketCommitmentRequest message or plain object
           * @returns Promise
           */
          public packetCommitment(
            request: ibc.core.channel.v1.IQueryPacketCommitmentRequest,
          ): Promise<ibc.core.channel.v1.QueryPacketCommitmentResponse>;

          /**
           * Calls PacketCommitments.
           * @param request QueryPacketCommitmentsRequest message or plain object
           * @param callback Node-style callback called with the error, if any, and QueryPacketCommitmentsResponse
           */
          public packetCommitments(
            request: ibc.core.channel.v1.IQueryPacketCommitmentsRequest,
            callback: ibc.core.channel.v1.Query.PacketCommitmentsCallback,
          ): void;

          /**
           * Calls PacketCommitments.
           * @param request QueryPacketCommitmentsRequest message or plain object
           * @returns Promise
           */
          public packetCommitments(
            request: ibc.core.channel.v1.IQueryPacketCommitmentsRequest,
          ): Promise<ibc.core.channel.v1.QueryPacketCommitmentsResponse>;

          /**
           * Calls PacketAcknowledgement.
           * @param request QueryPacketAcknowledgementRequest message or plain object
           * @param callback Node-style callback called with the error, if any, and QueryPacketAcknowledgementResponse
           */
          public packetAcknowledgement(
            request: ibc.core.channel.v1.IQueryPacketAcknowledgementRequest,
            callback: ibc.core.channel.v1.Query.PacketAcknowledgementCallback,
          ): void;

          /**
           * Calls PacketAcknowledgement.
           * @param request QueryPacketAcknowledgementRequest message or plain object
           * @returns Promise
           */
          public packetAcknowledgement(
            request: ibc.core.channel.v1.IQueryPacketAcknowledgementRequest,
          ): Promise<ibc.core.channel.v1.QueryPacketAcknowledgementResponse>;

          /**
           * Calls UnreceivedPackets.
           * @param request QueryUnreceivedPacketsRequest message or plain object
           * @param callback Node-style callback called with the error, if any, and QueryUnreceivedPacketsResponse
           */
          public unreceivedPackets(
            request: ibc.core.channel.v1.IQueryUnreceivedPacketsRequest,
            callback: ibc.core.channel.v1.Query.UnreceivedPacketsCallback,
          ): void;

          /**
           * Calls UnreceivedPackets.
           * @param request QueryUnreceivedPacketsRequest message or plain object
           * @returns Promise
           */
          public unreceivedPackets(
            request: ibc.core.channel.v1.IQueryUnreceivedPacketsRequest,
          ): Promise<ibc.core.channel.v1.QueryUnreceivedPacketsResponse>;

          /**
           * Calls UnrelayedAcks.
           * @param request QueryUnrelayedAcksRequest message or plain object
           * @param callback Node-style callback called with the error, if any, and QueryUnrelayedAcksResponse
           */
          public unrelayedAcks(
            request: ibc.core.channel.v1.IQueryUnrelayedAcksRequest,
            callback: ibc.core.channel.v1.Query.UnrelayedAcksCallback,
          ): void;

          /**
           * Calls UnrelayedAcks.
           * @param request QueryUnrelayedAcksRequest message or plain object
           * @returns Promise
           */
          public unrelayedAcks(
            request: ibc.core.channel.v1.IQueryUnrelayedAcksRequest,
          ): Promise<ibc.core.channel.v1.QueryUnrelayedAcksResponse>;

          /**
           * Calls NextSequenceReceive.
           * @param request QueryNextSequenceReceiveRequest message or plain object
           * @param callback Node-style callback called with the error, if any, and QueryNextSequenceReceiveResponse
           */
          public nextSequenceReceive(
            request: ibc.core.channel.v1.IQueryNextSequenceReceiveRequest,
            callback: ibc.core.channel.v1.Query.NextSequenceReceiveCallback,
          ): void;

          /**
           * Calls NextSequenceReceive.
           * @param request QueryNextSequenceReceiveRequest message or plain object
           * @returns Promise
           */
          public nextSequenceReceive(
            request: ibc.core.channel.v1.IQueryNextSequenceReceiveRequest,
          ): Promise<ibc.core.channel.v1.QueryNextSequenceReceiveResponse>;
        }

        namespace Query {
          /**
           * Callback as used by {@link ibc.core.channel.v1.Query#channel}.
           * @param error Error, if any
           * @param [response] QueryChannelResponse
           */
          type ChannelCallback = (
            error: Error | null,
            response?: ibc.core.channel.v1.QueryChannelResponse,
          ) => void;

          /**
           * Callback as used by {@link ibc.core.channel.v1.Query#channels}.
           * @param error Error, if any
           * @param [response] QueryChannelsResponse
           */
          type ChannelsCallback = (
            error: Error | null,
            response?: ibc.core.channel.v1.QueryChannelsResponse,
          ) => void;

          /**
           * Callback as used by {@link ibc.core.channel.v1.Query#connectionChannels}.
           * @param error Error, if any
           * @param [response] QueryConnectionChannelsResponse
           */
          type ConnectionChannelsCallback = (
            error: Error | null,
            response?: ibc.core.channel.v1.QueryConnectionChannelsResponse,
          ) => void;

          /**
           * Callback as used by {@link ibc.core.channel.v1.Query#channelClientState}.
           * @param error Error, if any
           * @param [response] QueryChannelClientStateResponse
           */
          type ChannelClientStateCallback = (
            error: Error | null,
            response?: ibc.core.channel.v1.QueryChannelClientStateResponse,
          ) => void;

          /**
           * Callback as used by {@link ibc.core.channel.v1.Query#channelConsensusState}.
           * @param error Error, if any
           * @param [response] QueryChannelConsensusStateResponse
           */
          type ChannelConsensusStateCallback = (
            error: Error | null,
            response?: ibc.core.channel.v1.QueryChannelConsensusStateResponse,
          ) => void;

          /**
           * Callback as used by {@link ibc.core.channel.v1.Query#packetCommitment}.
           * @param error Error, if any
           * @param [response] QueryPacketCommitmentResponse
           */
          type PacketCommitmentCallback = (
            error: Error | null,
            response?: ibc.core.channel.v1.QueryPacketCommitmentResponse,
          ) => void;

          /**
           * Callback as used by {@link ibc.core.channel.v1.Query#packetCommitments}.
           * @param error Error, if any
           * @param [response] QueryPacketCommitmentsResponse
           */
          type PacketCommitmentsCallback = (
            error: Error | null,
            response?: ibc.core.channel.v1.QueryPacketCommitmentsResponse,
          ) => void;

          /**
           * Callback as used by {@link ibc.core.channel.v1.Query#packetAcknowledgement}.
           * @param error Error, if any
           * @param [response] QueryPacketAcknowledgementResponse
           */
          type PacketAcknowledgementCallback = (
            error: Error | null,
            response?: ibc.core.channel.v1.QueryPacketAcknowledgementResponse,
          ) => void;

          /**
           * Callback as used by {@link ibc.core.channel.v1.Query#unreceivedPackets}.
           * @param error Error, if any
           * @param [response] QueryUnreceivedPacketsResponse
           */
          type UnreceivedPacketsCallback = (
            error: Error | null,
            response?: ibc.core.channel.v1.QueryUnreceivedPacketsResponse,
          ) => void;

          /**
           * Callback as used by {@link ibc.core.channel.v1.Query#unrelayedAcks}.
           * @param error Error, if any
           * @param [response] QueryUnrelayedAcksResponse
           */
          type UnrelayedAcksCallback = (
            error: Error | null,
            response?: ibc.core.channel.v1.QueryUnrelayedAcksResponse,
          ) => void;

          /**
           * Callback as used by {@link ibc.core.channel.v1.Query#nextSequenceReceive}.
           * @param error Error, if any
           * @param [response] QueryNextSequenceReceiveResponse
           */
          type NextSequenceReceiveCallback = (
            error: Error | null,
            response?: ibc.core.channel.v1.QueryNextSequenceReceiveResponse,
          ) => void;
        }

        /** Properties of a QueryChannelRequest. */
        interface IQueryChannelRequest {
          /** QueryChannelRequest portId */
          portId?: string | null;

          /** QueryChannelRequest channelId */
          channelId?: string | null;
        }

        /** Represents a QueryChannelRequest. */
        class QueryChannelRequest implements IQueryChannelRequest {
          /**
           * Constructs a new QueryChannelRequest.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryChannelRequest);

          /** QueryChannelRequest portId. */
          public portId: string;

          /** QueryChannelRequest channelId. */
          public channelId: string;

          /**
           * Creates a new QueryChannelRequest instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryChannelRequest instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryChannelRequest,
          ): ibc.core.channel.v1.QueryChannelRequest;

          /**
           * Encodes the specified QueryChannelRequest message. Does not implicitly {@link ibc.core.channel.v1.QueryChannelRequest.verify|verify} messages.
           * @param m QueryChannelRequest message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryChannelRequest,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryChannelRequest message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryChannelRequest
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryChannelRequest;
        }

        /** Properties of a QueryChannelResponse. */
        interface IQueryChannelResponse {
          /** QueryChannelResponse channel */
          channel?: ibc.core.channel.v1.IChannel | null;

          /** QueryChannelResponse proof */
          proof?: Uint8Array | null;

          /** QueryChannelResponse proofPath */
          proofPath?: string | null;

          /** QueryChannelResponse proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;
        }

        /** Represents a QueryChannelResponse. */
        class QueryChannelResponse implements IQueryChannelResponse {
          /**
           * Constructs a new QueryChannelResponse.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryChannelResponse);

          /** QueryChannelResponse channel. */
          public channel?: ibc.core.channel.v1.IChannel | null;

          /** QueryChannelResponse proof. */
          public proof: Uint8Array;

          /** QueryChannelResponse proofPath. */
          public proofPath: string;

          /** QueryChannelResponse proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /**
           * Creates a new QueryChannelResponse instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryChannelResponse instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryChannelResponse,
          ): ibc.core.channel.v1.QueryChannelResponse;

          /**
           * Encodes the specified QueryChannelResponse message. Does not implicitly {@link ibc.core.channel.v1.QueryChannelResponse.verify|verify} messages.
           * @param m QueryChannelResponse message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryChannelResponse,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryChannelResponse message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryChannelResponse
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryChannelResponse;
        }

        /** Properties of a QueryChannelsRequest. */
        interface IQueryChannelsRequest {
          /** QueryChannelsRequest pagination */
          pagination?: cosmos.base.query.v1beta1.IPageRequest | null;
        }

        /** Represents a QueryChannelsRequest. */
        class QueryChannelsRequest implements IQueryChannelsRequest {
          /**
           * Constructs a new QueryChannelsRequest.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryChannelsRequest);

          /** QueryChannelsRequest pagination. */
          public pagination?: cosmos.base.query.v1beta1.IPageRequest | null;

          /**
           * Creates a new QueryChannelsRequest instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryChannelsRequest instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryChannelsRequest,
          ): ibc.core.channel.v1.QueryChannelsRequest;

          /**
           * Encodes the specified QueryChannelsRequest message. Does not implicitly {@link ibc.core.channel.v1.QueryChannelsRequest.verify|verify} messages.
           * @param m QueryChannelsRequest message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryChannelsRequest,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryChannelsRequest message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryChannelsRequest
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryChannelsRequest;
        }

        /** Properties of a QueryChannelsResponse. */
        interface IQueryChannelsResponse {
          /** QueryChannelsResponse channels */
          channels?: ibc.core.channel.v1.IIdentifiedChannel[] | null;

          /** QueryChannelsResponse pagination */
          pagination?: cosmos.base.query.v1beta1.IPageResponse | null;

          /** QueryChannelsResponse height */
          height?: ibc.core.client.v1.IHeight | null;
        }

        /** Represents a QueryChannelsResponse. */
        class QueryChannelsResponse implements IQueryChannelsResponse {
          /**
           * Constructs a new QueryChannelsResponse.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryChannelsResponse);

          /** QueryChannelsResponse channels. */
          public channels: ibc.core.channel.v1.IIdentifiedChannel[];

          /** QueryChannelsResponse pagination. */
          public pagination?: cosmos.base.query.v1beta1.IPageResponse | null;

          /** QueryChannelsResponse height. */
          public height?: ibc.core.client.v1.IHeight | null;

          /**
           * Creates a new QueryChannelsResponse instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryChannelsResponse instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryChannelsResponse,
          ): ibc.core.channel.v1.QueryChannelsResponse;

          /**
           * Encodes the specified QueryChannelsResponse message. Does not implicitly {@link ibc.core.channel.v1.QueryChannelsResponse.verify|verify} messages.
           * @param m QueryChannelsResponse message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryChannelsResponse,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryChannelsResponse message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryChannelsResponse
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryChannelsResponse;
        }

        /** Properties of a QueryConnectionChannelsRequest. */
        interface IQueryConnectionChannelsRequest {
          /** QueryConnectionChannelsRequest connection */
          connection?: string | null;

          /** QueryConnectionChannelsRequest pagination */
          pagination?: cosmos.base.query.v1beta1.IPageRequest | null;
        }

        /** Represents a QueryConnectionChannelsRequest. */
        class QueryConnectionChannelsRequest implements IQueryConnectionChannelsRequest {
          /**
           * Constructs a new QueryConnectionChannelsRequest.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryConnectionChannelsRequest);

          /** QueryConnectionChannelsRequest connection. */
          public connection: string;

          /** QueryConnectionChannelsRequest pagination. */
          public pagination?: cosmos.base.query.v1beta1.IPageRequest | null;

          /**
           * Creates a new QueryConnectionChannelsRequest instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryConnectionChannelsRequest instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryConnectionChannelsRequest,
          ): ibc.core.channel.v1.QueryConnectionChannelsRequest;

          /**
           * Encodes the specified QueryConnectionChannelsRequest message. Does not implicitly {@link ibc.core.channel.v1.QueryConnectionChannelsRequest.verify|verify} messages.
           * @param m QueryConnectionChannelsRequest message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryConnectionChannelsRequest,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryConnectionChannelsRequest message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryConnectionChannelsRequest
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryConnectionChannelsRequest;
        }

        /** Properties of a QueryConnectionChannelsResponse. */
        interface IQueryConnectionChannelsResponse {
          /** QueryConnectionChannelsResponse channels */
          channels?: ibc.core.channel.v1.IIdentifiedChannel[] | null;

          /** QueryConnectionChannelsResponse pagination */
          pagination?: cosmos.base.query.v1beta1.IPageResponse | null;

          /** QueryConnectionChannelsResponse height */
          height?: ibc.core.client.v1.IHeight | null;
        }

        /** Represents a QueryConnectionChannelsResponse. */
        class QueryConnectionChannelsResponse implements IQueryConnectionChannelsResponse {
          /**
           * Constructs a new QueryConnectionChannelsResponse.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryConnectionChannelsResponse);

          /** QueryConnectionChannelsResponse channels. */
          public channels: ibc.core.channel.v1.IIdentifiedChannel[];

          /** QueryConnectionChannelsResponse pagination. */
          public pagination?: cosmos.base.query.v1beta1.IPageResponse | null;

          /** QueryConnectionChannelsResponse height. */
          public height?: ibc.core.client.v1.IHeight | null;

          /**
           * Creates a new QueryConnectionChannelsResponse instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryConnectionChannelsResponse instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryConnectionChannelsResponse,
          ): ibc.core.channel.v1.QueryConnectionChannelsResponse;

          /**
           * Encodes the specified QueryConnectionChannelsResponse message. Does not implicitly {@link ibc.core.channel.v1.QueryConnectionChannelsResponse.verify|verify} messages.
           * @param m QueryConnectionChannelsResponse message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryConnectionChannelsResponse,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryConnectionChannelsResponse message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryConnectionChannelsResponse
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryConnectionChannelsResponse;
        }

        /** Properties of a QueryChannelClientStateRequest. */
        interface IQueryChannelClientStateRequest {
          /** QueryChannelClientStateRequest portId */
          portId?: string | null;

          /** QueryChannelClientStateRequest channelId */
          channelId?: string | null;
        }

        /** Represents a QueryChannelClientStateRequest. */
        class QueryChannelClientStateRequest implements IQueryChannelClientStateRequest {
          /**
           * Constructs a new QueryChannelClientStateRequest.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryChannelClientStateRequest);

          /** QueryChannelClientStateRequest portId. */
          public portId: string;

          /** QueryChannelClientStateRequest channelId. */
          public channelId: string;

          /**
           * Creates a new QueryChannelClientStateRequest instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryChannelClientStateRequest instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryChannelClientStateRequest,
          ): ibc.core.channel.v1.QueryChannelClientStateRequest;

          /**
           * Encodes the specified QueryChannelClientStateRequest message. Does not implicitly {@link ibc.core.channel.v1.QueryChannelClientStateRequest.verify|verify} messages.
           * @param m QueryChannelClientStateRequest message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryChannelClientStateRequest,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryChannelClientStateRequest message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryChannelClientStateRequest
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryChannelClientStateRequest;
        }

        /** Properties of a QueryChannelClientStateResponse. */
        interface IQueryChannelClientStateResponse {
          /** QueryChannelClientStateResponse identifiedClientState */
          identifiedClientState?: ibc.core.client.v1.IIdentifiedClientState | null;

          /** QueryChannelClientStateResponse proof */
          proof?: Uint8Array | null;

          /** QueryChannelClientStateResponse proofPath */
          proofPath?: string | null;

          /** QueryChannelClientStateResponse proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;
        }

        /** Represents a QueryChannelClientStateResponse. */
        class QueryChannelClientStateResponse implements IQueryChannelClientStateResponse {
          /**
           * Constructs a new QueryChannelClientStateResponse.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryChannelClientStateResponse);

          /** QueryChannelClientStateResponse identifiedClientState. */
          public identifiedClientState?: ibc.core.client.v1.IIdentifiedClientState | null;

          /** QueryChannelClientStateResponse proof. */
          public proof: Uint8Array;

          /** QueryChannelClientStateResponse proofPath. */
          public proofPath: string;

          /** QueryChannelClientStateResponse proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /**
           * Creates a new QueryChannelClientStateResponse instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryChannelClientStateResponse instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryChannelClientStateResponse,
          ): ibc.core.channel.v1.QueryChannelClientStateResponse;

          /**
           * Encodes the specified QueryChannelClientStateResponse message. Does not implicitly {@link ibc.core.channel.v1.QueryChannelClientStateResponse.verify|verify} messages.
           * @param m QueryChannelClientStateResponse message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryChannelClientStateResponse,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryChannelClientStateResponse message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryChannelClientStateResponse
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryChannelClientStateResponse;
        }

        /** Properties of a QueryChannelConsensusStateRequest. */
        interface IQueryChannelConsensusStateRequest {
          /** QueryChannelConsensusStateRequest portId */
          portId?: string | null;

          /** QueryChannelConsensusStateRequest channelId */
          channelId?: string | null;

          /** QueryChannelConsensusStateRequest versionNumber */
          versionNumber?: Long | null;

          /** QueryChannelConsensusStateRequest versionHeight */
          versionHeight?: Long | null;
        }

        /** Represents a QueryChannelConsensusStateRequest. */
        class QueryChannelConsensusStateRequest implements IQueryChannelConsensusStateRequest {
          /**
           * Constructs a new QueryChannelConsensusStateRequest.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryChannelConsensusStateRequest);

          /** QueryChannelConsensusStateRequest portId. */
          public portId: string;

          /** QueryChannelConsensusStateRequest channelId. */
          public channelId: string;

          /** QueryChannelConsensusStateRequest versionNumber. */
          public versionNumber: Long;

          /** QueryChannelConsensusStateRequest versionHeight. */
          public versionHeight: Long;

          /**
           * Creates a new QueryChannelConsensusStateRequest instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryChannelConsensusStateRequest instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryChannelConsensusStateRequest,
          ): ibc.core.channel.v1.QueryChannelConsensusStateRequest;

          /**
           * Encodes the specified QueryChannelConsensusStateRequest message. Does not implicitly {@link ibc.core.channel.v1.QueryChannelConsensusStateRequest.verify|verify} messages.
           * @param m QueryChannelConsensusStateRequest message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryChannelConsensusStateRequest,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryChannelConsensusStateRequest message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryChannelConsensusStateRequest
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryChannelConsensusStateRequest;
        }

        /** Properties of a QueryChannelConsensusStateResponse. */
        interface IQueryChannelConsensusStateResponse {
          /** QueryChannelConsensusStateResponse consensusState */
          consensusState?: google.protobuf.IAny | null;

          /** QueryChannelConsensusStateResponse clientId */
          clientId?: string | null;

          /** QueryChannelConsensusStateResponse proof */
          proof?: Uint8Array | null;

          /** QueryChannelConsensusStateResponse proofPath */
          proofPath?: string | null;

          /** QueryChannelConsensusStateResponse proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;
        }

        /** Represents a QueryChannelConsensusStateResponse. */
        class QueryChannelConsensusStateResponse implements IQueryChannelConsensusStateResponse {
          /**
           * Constructs a new QueryChannelConsensusStateResponse.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryChannelConsensusStateResponse);

          /** QueryChannelConsensusStateResponse consensusState. */
          public consensusState?: google.protobuf.IAny | null;

          /** QueryChannelConsensusStateResponse clientId. */
          public clientId: string;

          /** QueryChannelConsensusStateResponse proof. */
          public proof: Uint8Array;

          /** QueryChannelConsensusStateResponse proofPath. */
          public proofPath: string;

          /** QueryChannelConsensusStateResponse proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /**
           * Creates a new QueryChannelConsensusStateResponse instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryChannelConsensusStateResponse instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryChannelConsensusStateResponse,
          ): ibc.core.channel.v1.QueryChannelConsensusStateResponse;

          /**
           * Encodes the specified QueryChannelConsensusStateResponse message. Does not implicitly {@link ibc.core.channel.v1.QueryChannelConsensusStateResponse.verify|verify} messages.
           * @param m QueryChannelConsensusStateResponse message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryChannelConsensusStateResponse,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryChannelConsensusStateResponse message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryChannelConsensusStateResponse
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryChannelConsensusStateResponse;
        }

        /** Properties of a QueryPacketCommitmentRequest. */
        interface IQueryPacketCommitmentRequest {
          /** QueryPacketCommitmentRequest portId */
          portId?: string | null;

          /** QueryPacketCommitmentRequest channelId */
          channelId?: string | null;

          /** QueryPacketCommitmentRequest sequence */
          sequence?: Long | null;
        }

        /** Represents a QueryPacketCommitmentRequest. */
        class QueryPacketCommitmentRequest implements IQueryPacketCommitmentRequest {
          /**
           * Constructs a new QueryPacketCommitmentRequest.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryPacketCommitmentRequest);

          /** QueryPacketCommitmentRequest portId. */
          public portId: string;

          /** QueryPacketCommitmentRequest channelId. */
          public channelId: string;

          /** QueryPacketCommitmentRequest sequence. */
          public sequence: Long;

          /**
           * Creates a new QueryPacketCommitmentRequest instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryPacketCommitmentRequest instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryPacketCommitmentRequest,
          ): ibc.core.channel.v1.QueryPacketCommitmentRequest;

          /**
           * Encodes the specified QueryPacketCommitmentRequest message. Does not implicitly {@link ibc.core.channel.v1.QueryPacketCommitmentRequest.verify|verify} messages.
           * @param m QueryPacketCommitmentRequest message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryPacketCommitmentRequest,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryPacketCommitmentRequest message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryPacketCommitmentRequest
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryPacketCommitmentRequest;
        }

        /** Properties of a QueryPacketCommitmentResponse. */
        interface IQueryPacketCommitmentResponse {
          /** QueryPacketCommitmentResponse commitment */
          commitment?: Uint8Array | null;

          /** QueryPacketCommitmentResponse proof */
          proof?: Uint8Array | null;

          /** QueryPacketCommitmentResponse proofPath */
          proofPath?: string | null;

          /** QueryPacketCommitmentResponse proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;
        }

        /** Represents a QueryPacketCommitmentResponse. */
        class QueryPacketCommitmentResponse implements IQueryPacketCommitmentResponse {
          /**
           * Constructs a new QueryPacketCommitmentResponse.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryPacketCommitmentResponse);

          /** QueryPacketCommitmentResponse commitment. */
          public commitment: Uint8Array;

          /** QueryPacketCommitmentResponse proof. */
          public proof: Uint8Array;

          /** QueryPacketCommitmentResponse proofPath. */
          public proofPath: string;

          /** QueryPacketCommitmentResponse proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /**
           * Creates a new QueryPacketCommitmentResponse instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryPacketCommitmentResponse instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryPacketCommitmentResponse,
          ): ibc.core.channel.v1.QueryPacketCommitmentResponse;

          /**
           * Encodes the specified QueryPacketCommitmentResponse message. Does not implicitly {@link ibc.core.channel.v1.QueryPacketCommitmentResponse.verify|verify} messages.
           * @param m QueryPacketCommitmentResponse message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryPacketCommitmentResponse,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryPacketCommitmentResponse message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryPacketCommitmentResponse
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryPacketCommitmentResponse;
        }

        /** Properties of a QueryPacketCommitmentsRequest. */
        interface IQueryPacketCommitmentsRequest {
          /** QueryPacketCommitmentsRequest portId */
          portId?: string | null;

          /** QueryPacketCommitmentsRequest channelId */
          channelId?: string | null;

          /** QueryPacketCommitmentsRequest pagination */
          pagination?: cosmos.base.query.v1beta1.IPageRequest | null;
        }

        /** Represents a QueryPacketCommitmentsRequest. */
        class QueryPacketCommitmentsRequest implements IQueryPacketCommitmentsRequest {
          /**
           * Constructs a new QueryPacketCommitmentsRequest.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryPacketCommitmentsRequest);

          /** QueryPacketCommitmentsRequest portId. */
          public portId: string;

          /** QueryPacketCommitmentsRequest channelId. */
          public channelId: string;

          /** QueryPacketCommitmentsRequest pagination. */
          public pagination?: cosmos.base.query.v1beta1.IPageRequest | null;

          /**
           * Creates a new QueryPacketCommitmentsRequest instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryPacketCommitmentsRequest instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryPacketCommitmentsRequest,
          ): ibc.core.channel.v1.QueryPacketCommitmentsRequest;

          /**
           * Encodes the specified QueryPacketCommitmentsRequest message. Does not implicitly {@link ibc.core.channel.v1.QueryPacketCommitmentsRequest.verify|verify} messages.
           * @param m QueryPacketCommitmentsRequest message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryPacketCommitmentsRequest,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryPacketCommitmentsRequest message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryPacketCommitmentsRequest
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryPacketCommitmentsRequest;
        }

        /** Properties of a QueryPacketCommitmentsResponse. */
        interface IQueryPacketCommitmentsResponse {
          /** QueryPacketCommitmentsResponse commitments */
          commitments?: ibc.core.channel.v1.IPacketAckCommitment[] | null;

          /** QueryPacketCommitmentsResponse pagination */
          pagination?: cosmos.base.query.v1beta1.IPageResponse | null;

          /** QueryPacketCommitmentsResponse height */
          height?: ibc.core.client.v1.IHeight | null;
        }

        /** Represents a QueryPacketCommitmentsResponse. */
        class QueryPacketCommitmentsResponse implements IQueryPacketCommitmentsResponse {
          /**
           * Constructs a new QueryPacketCommitmentsResponse.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryPacketCommitmentsResponse);

          /** QueryPacketCommitmentsResponse commitments. */
          public commitments: ibc.core.channel.v1.IPacketAckCommitment[];

          /** QueryPacketCommitmentsResponse pagination. */
          public pagination?: cosmos.base.query.v1beta1.IPageResponse | null;

          /** QueryPacketCommitmentsResponse height. */
          public height?: ibc.core.client.v1.IHeight | null;

          /**
           * Creates a new QueryPacketCommitmentsResponse instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryPacketCommitmentsResponse instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryPacketCommitmentsResponse,
          ): ibc.core.channel.v1.QueryPacketCommitmentsResponse;

          /**
           * Encodes the specified QueryPacketCommitmentsResponse message. Does not implicitly {@link ibc.core.channel.v1.QueryPacketCommitmentsResponse.verify|verify} messages.
           * @param m QueryPacketCommitmentsResponse message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryPacketCommitmentsResponse,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryPacketCommitmentsResponse message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryPacketCommitmentsResponse
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryPacketCommitmentsResponse;
        }

        /** Properties of a QueryPacketAcknowledgementRequest. */
        interface IQueryPacketAcknowledgementRequest {
          /** QueryPacketAcknowledgementRequest portId */
          portId?: string | null;

          /** QueryPacketAcknowledgementRequest channelId */
          channelId?: string | null;

          /** QueryPacketAcknowledgementRequest sequence */
          sequence?: Long | null;
        }

        /** Represents a QueryPacketAcknowledgementRequest. */
        class QueryPacketAcknowledgementRequest implements IQueryPacketAcknowledgementRequest {
          /**
           * Constructs a new QueryPacketAcknowledgementRequest.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryPacketAcknowledgementRequest);

          /** QueryPacketAcknowledgementRequest portId. */
          public portId: string;

          /** QueryPacketAcknowledgementRequest channelId. */
          public channelId: string;

          /** QueryPacketAcknowledgementRequest sequence. */
          public sequence: Long;

          /**
           * Creates a new QueryPacketAcknowledgementRequest instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryPacketAcknowledgementRequest instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryPacketAcknowledgementRequest,
          ): ibc.core.channel.v1.QueryPacketAcknowledgementRequest;

          /**
           * Encodes the specified QueryPacketAcknowledgementRequest message. Does not implicitly {@link ibc.core.channel.v1.QueryPacketAcknowledgementRequest.verify|verify} messages.
           * @param m QueryPacketAcknowledgementRequest message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryPacketAcknowledgementRequest,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryPacketAcknowledgementRequest message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryPacketAcknowledgementRequest
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryPacketAcknowledgementRequest;
        }

        /** Properties of a QueryPacketAcknowledgementResponse. */
        interface IQueryPacketAcknowledgementResponse {
          /** QueryPacketAcknowledgementResponse acknowledgement */
          acknowledgement?: Uint8Array | null;

          /** QueryPacketAcknowledgementResponse proof */
          proof?: Uint8Array | null;

          /** QueryPacketAcknowledgementResponse proofPath */
          proofPath?: string | null;

          /** QueryPacketAcknowledgementResponse proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;
        }

        /** Represents a QueryPacketAcknowledgementResponse. */
        class QueryPacketAcknowledgementResponse implements IQueryPacketAcknowledgementResponse {
          /**
           * Constructs a new QueryPacketAcknowledgementResponse.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryPacketAcknowledgementResponse);

          /** QueryPacketAcknowledgementResponse acknowledgement. */
          public acknowledgement: Uint8Array;

          /** QueryPacketAcknowledgementResponse proof. */
          public proof: Uint8Array;

          /** QueryPacketAcknowledgementResponse proofPath. */
          public proofPath: string;

          /** QueryPacketAcknowledgementResponse proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /**
           * Creates a new QueryPacketAcknowledgementResponse instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryPacketAcknowledgementResponse instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryPacketAcknowledgementResponse,
          ): ibc.core.channel.v1.QueryPacketAcknowledgementResponse;

          /**
           * Encodes the specified QueryPacketAcknowledgementResponse message. Does not implicitly {@link ibc.core.channel.v1.QueryPacketAcknowledgementResponse.verify|verify} messages.
           * @param m QueryPacketAcknowledgementResponse message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryPacketAcknowledgementResponse,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryPacketAcknowledgementResponse message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryPacketAcknowledgementResponse
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryPacketAcknowledgementResponse;
        }

        /** Properties of a QueryUnreceivedPacketsRequest. */
        interface IQueryUnreceivedPacketsRequest {
          /** QueryUnreceivedPacketsRequest portId */
          portId?: string | null;

          /** QueryUnreceivedPacketsRequest channelId */
          channelId?: string | null;

          /** QueryUnreceivedPacketsRequest packetCommitmentSequences */
          packetCommitmentSequences?: Long[] | null;
        }

        /** Represents a QueryUnreceivedPacketsRequest. */
        class QueryUnreceivedPacketsRequest implements IQueryUnreceivedPacketsRequest {
          /**
           * Constructs a new QueryUnreceivedPacketsRequest.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryUnreceivedPacketsRequest);

          /** QueryUnreceivedPacketsRequest portId. */
          public portId: string;

          /** QueryUnreceivedPacketsRequest channelId. */
          public channelId: string;

          /** QueryUnreceivedPacketsRequest packetCommitmentSequences. */
          public packetCommitmentSequences: Long[];

          /**
           * Creates a new QueryUnreceivedPacketsRequest instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryUnreceivedPacketsRequest instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryUnreceivedPacketsRequest,
          ): ibc.core.channel.v1.QueryUnreceivedPacketsRequest;

          /**
           * Encodes the specified QueryUnreceivedPacketsRequest message. Does not implicitly {@link ibc.core.channel.v1.QueryUnreceivedPacketsRequest.verify|verify} messages.
           * @param m QueryUnreceivedPacketsRequest message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryUnreceivedPacketsRequest,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryUnreceivedPacketsRequest message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryUnreceivedPacketsRequest
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryUnreceivedPacketsRequest;
        }

        /** Properties of a QueryUnreceivedPacketsResponse. */
        interface IQueryUnreceivedPacketsResponse {
          /** QueryUnreceivedPacketsResponse sequences */
          sequences?: Long[] | null;

          /** QueryUnreceivedPacketsResponse height */
          height?: ibc.core.client.v1.IHeight | null;
        }

        /** Represents a QueryUnreceivedPacketsResponse. */
        class QueryUnreceivedPacketsResponse implements IQueryUnreceivedPacketsResponse {
          /**
           * Constructs a new QueryUnreceivedPacketsResponse.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryUnreceivedPacketsResponse);

          /** QueryUnreceivedPacketsResponse sequences. */
          public sequences: Long[];

          /** QueryUnreceivedPacketsResponse height. */
          public height?: ibc.core.client.v1.IHeight | null;

          /**
           * Creates a new QueryUnreceivedPacketsResponse instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryUnreceivedPacketsResponse instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryUnreceivedPacketsResponse,
          ): ibc.core.channel.v1.QueryUnreceivedPacketsResponse;

          /**
           * Encodes the specified QueryUnreceivedPacketsResponse message. Does not implicitly {@link ibc.core.channel.v1.QueryUnreceivedPacketsResponse.verify|verify} messages.
           * @param m QueryUnreceivedPacketsResponse message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryUnreceivedPacketsResponse,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryUnreceivedPacketsResponse message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryUnreceivedPacketsResponse
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryUnreceivedPacketsResponse;
        }

        /** Properties of a QueryUnrelayedAcksRequest. */
        interface IQueryUnrelayedAcksRequest {
          /** QueryUnrelayedAcksRequest portId */
          portId?: string | null;

          /** QueryUnrelayedAcksRequest channelId */
          channelId?: string | null;

          /** QueryUnrelayedAcksRequest packetCommitmentSequences */
          packetCommitmentSequences?: Long[] | null;
        }

        /** Represents a QueryUnrelayedAcksRequest. */
        class QueryUnrelayedAcksRequest implements IQueryUnrelayedAcksRequest {
          /**
           * Constructs a new QueryUnrelayedAcksRequest.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryUnrelayedAcksRequest);

          /** QueryUnrelayedAcksRequest portId. */
          public portId: string;

          /** QueryUnrelayedAcksRequest channelId. */
          public channelId: string;

          /** QueryUnrelayedAcksRequest packetCommitmentSequences. */
          public packetCommitmentSequences: Long[];

          /**
           * Creates a new QueryUnrelayedAcksRequest instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryUnrelayedAcksRequest instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryUnrelayedAcksRequest,
          ): ibc.core.channel.v1.QueryUnrelayedAcksRequest;

          /**
           * Encodes the specified QueryUnrelayedAcksRequest message. Does not implicitly {@link ibc.core.channel.v1.QueryUnrelayedAcksRequest.verify|verify} messages.
           * @param m QueryUnrelayedAcksRequest message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryUnrelayedAcksRequest,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryUnrelayedAcksRequest message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryUnrelayedAcksRequest
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryUnrelayedAcksRequest;
        }

        /** Properties of a QueryUnrelayedAcksResponse. */
        interface IQueryUnrelayedAcksResponse {
          /** QueryUnrelayedAcksResponse sequences */
          sequences?: Long[] | null;

          /** QueryUnrelayedAcksResponse height */
          height?: ibc.core.client.v1.IHeight | null;
        }

        /** Represents a QueryUnrelayedAcksResponse. */
        class QueryUnrelayedAcksResponse implements IQueryUnrelayedAcksResponse {
          /**
           * Constructs a new QueryUnrelayedAcksResponse.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryUnrelayedAcksResponse);

          /** QueryUnrelayedAcksResponse sequences. */
          public sequences: Long[];

          /** QueryUnrelayedAcksResponse height. */
          public height?: ibc.core.client.v1.IHeight | null;

          /**
           * Creates a new QueryUnrelayedAcksResponse instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryUnrelayedAcksResponse instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryUnrelayedAcksResponse,
          ): ibc.core.channel.v1.QueryUnrelayedAcksResponse;

          /**
           * Encodes the specified QueryUnrelayedAcksResponse message. Does not implicitly {@link ibc.core.channel.v1.QueryUnrelayedAcksResponse.verify|verify} messages.
           * @param m QueryUnrelayedAcksResponse message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryUnrelayedAcksResponse,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryUnrelayedAcksResponse message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryUnrelayedAcksResponse
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryUnrelayedAcksResponse;
        }

        /** Properties of a QueryNextSequenceReceiveRequest. */
        interface IQueryNextSequenceReceiveRequest {
          /** QueryNextSequenceReceiveRequest portId */
          portId?: string | null;

          /** QueryNextSequenceReceiveRequest channelId */
          channelId?: string | null;
        }

        /** Represents a QueryNextSequenceReceiveRequest. */
        class QueryNextSequenceReceiveRequest implements IQueryNextSequenceReceiveRequest {
          /**
           * Constructs a new QueryNextSequenceReceiveRequest.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryNextSequenceReceiveRequest);

          /** QueryNextSequenceReceiveRequest portId. */
          public portId: string;

          /** QueryNextSequenceReceiveRequest channelId. */
          public channelId: string;

          /**
           * Creates a new QueryNextSequenceReceiveRequest instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryNextSequenceReceiveRequest instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryNextSequenceReceiveRequest,
          ): ibc.core.channel.v1.QueryNextSequenceReceiveRequest;

          /**
           * Encodes the specified QueryNextSequenceReceiveRequest message. Does not implicitly {@link ibc.core.channel.v1.QueryNextSequenceReceiveRequest.verify|verify} messages.
           * @param m QueryNextSequenceReceiveRequest message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryNextSequenceReceiveRequest,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryNextSequenceReceiveRequest message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryNextSequenceReceiveRequest
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryNextSequenceReceiveRequest;
        }

        /** Properties of a QueryNextSequenceReceiveResponse. */
        interface IQueryNextSequenceReceiveResponse {
          /** QueryNextSequenceReceiveResponse nextSequenceReceive */
          nextSequenceReceive?: Long | null;

          /** QueryNextSequenceReceiveResponse proof */
          proof?: Uint8Array | null;

          /** QueryNextSequenceReceiveResponse proofPath */
          proofPath?: string | null;

          /** QueryNextSequenceReceiveResponse proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;
        }

        /** Represents a QueryNextSequenceReceiveResponse. */
        class QueryNextSequenceReceiveResponse implements IQueryNextSequenceReceiveResponse {
          /**
           * Constructs a new QueryNextSequenceReceiveResponse.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.channel.v1.IQueryNextSequenceReceiveResponse);

          /** QueryNextSequenceReceiveResponse nextSequenceReceive. */
          public nextSequenceReceive: Long;

          /** QueryNextSequenceReceiveResponse proof. */
          public proof: Uint8Array;

          /** QueryNextSequenceReceiveResponse proofPath. */
          public proofPath: string;

          /** QueryNextSequenceReceiveResponse proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /**
           * Creates a new QueryNextSequenceReceiveResponse instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryNextSequenceReceiveResponse instance
           */
          public static create(
            properties?: ibc.core.channel.v1.IQueryNextSequenceReceiveResponse,
          ): ibc.core.channel.v1.QueryNextSequenceReceiveResponse;

          /**
           * Encodes the specified QueryNextSequenceReceiveResponse message. Does not implicitly {@link ibc.core.channel.v1.QueryNextSequenceReceiveResponse.verify|verify} messages.
           * @param m QueryNextSequenceReceiveResponse message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.channel.v1.IQueryNextSequenceReceiveResponse,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryNextSequenceReceiveResponse message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryNextSequenceReceiveResponse
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.channel.v1.QueryNextSequenceReceiveResponse;
        }
      }
    }

    /** Namespace client. */
    namespace client {
      /** Namespace v1. */
      namespace v1 {
        /** Properties of an IdentifiedClientState. */
        interface IIdentifiedClientState {
          /** IdentifiedClientState clientId */
          clientId?: string | null;

          /** IdentifiedClientState clientState */
          clientState?: google.protobuf.IAny | null;
        }

        /** Represents an IdentifiedClientState. */
        class IdentifiedClientState implements IIdentifiedClientState {
          /**
           * Constructs a new IdentifiedClientState.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.client.v1.IIdentifiedClientState);

          /** IdentifiedClientState clientId. */
          public clientId: string;

          /** IdentifiedClientState clientState. */
          public clientState?: google.protobuf.IAny | null;

          /**
           * Creates a new IdentifiedClientState instance using the specified properties.
           * @param [properties] Properties to set
           * @returns IdentifiedClientState instance
           */
          public static create(
            properties?: ibc.core.client.v1.IIdentifiedClientState,
          ): ibc.core.client.v1.IdentifiedClientState;

          /**
           * Encodes the specified IdentifiedClientState message. Does not implicitly {@link ibc.core.client.v1.IdentifiedClientState.verify|verify} messages.
           * @param m IdentifiedClientState message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.client.v1.IIdentifiedClientState,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes an IdentifiedClientState message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns IdentifiedClientState
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.client.v1.IdentifiedClientState;
        }

        /** Properties of a ConsensusStateWithHeight. */
        interface IConsensusStateWithHeight {
          /** ConsensusStateWithHeight height */
          height?: ibc.core.client.v1.IHeight | null;

          /** ConsensusStateWithHeight consensusState */
          consensusState?: google.protobuf.IAny | null;
        }

        /** Represents a ConsensusStateWithHeight. */
        class ConsensusStateWithHeight implements IConsensusStateWithHeight {
          /**
           * Constructs a new ConsensusStateWithHeight.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.client.v1.IConsensusStateWithHeight);

          /** ConsensusStateWithHeight height. */
          public height?: ibc.core.client.v1.IHeight | null;

          /** ConsensusStateWithHeight consensusState. */
          public consensusState?: google.protobuf.IAny | null;

          /**
           * Creates a new ConsensusStateWithHeight instance using the specified properties.
           * @param [properties] Properties to set
           * @returns ConsensusStateWithHeight instance
           */
          public static create(
            properties?: ibc.core.client.v1.IConsensusStateWithHeight,
          ): ibc.core.client.v1.ConsensusStateWithHeight;

          /**
           * Encodes the specified ConsensusStateWithHeight message. Does not implicitly {@link ibc.core.client.v1.ConsensusStateWithHeight.verify|verify} messages.
           * @param m ConsensusStateWithHeight message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.client.v1.IConsensusStateWithHeight,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a ConsensusStateWithHeight message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns ConsensusStateWithHeight
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.client.v1.ConsensusStateWithHeight;
        }

        /** Properties of a ClientConsensusStates. */
        interface IClientConsensusStates {
          /** ClientConsensusStates clientId */
          clientId?: string | null;

          /** ClientConsensusStates consensusStates */
          consensusStates?: ibc.core.client.v1.IConsensusStateWithHeight[] | null;
        }

        /** Represents a ClientConsensusStates. */
        class ClientConsensusStates implements IClientConsensusStates {
          /**
           * Constructs a new ClientConsensusStates.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.client.v1.IClientConsensusStates);

          /** ClientConsensusStates clientId. */
          public clientId: string;

          /** ClientConsensusStates consensusStates. */
          public consensusStates: ibc.core.client.v1.IConsensusStateWithHeight[];

          /**
           * Creates a new ClientConsensusStates instance using the specified properties.
           * @param [properties] Properties to set
           * @returns ClientConsensusStates instance
           */
          public static create(
            properties?: ibc.core.client.v1.IClientConsensusStates,
          ): ibc.core.client.v1.ClientConsensusStates;

          /**
           * Encodes the specified ClientConsensusStates message. Does not implicitly {@link ibc.core.client.v1.ClientConsensusStates.verify|verify} messages.
           * @param m ClientConsensusStates message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.client.v1.IClientConsensusStates,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a ClientConsensusStates message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns ClientConsensusStates
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.client.v1.ClientConsensusStates;
        }

        /** Properties of a ClientUpdateProposal. */
        interface IClientUpdateProposal {
          /** ClientUpdateProposal title */
          title?: string | null;

          /** ClientUpdateProposal description */
          description?: string | null;

          /** ClientUpdateProposal clientId */
          clientId?: string | null;

          /** ClientUpdateProposal header */
          header?: google.protobuf.IAny | null;
        }

        /** Represents a ClientUpdateProposal. */
        class ClientUpdateProposal implements IClientUpdateProposal {
          /**
           * Constructs a new ClientUpdateProposal.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.client.v1.IClientUpdateProposal);

          /** ClientUpdateProposal title. */
          public title: string;

          /** ClientUpdateProposal description. */
          public description: string;

          /** ClientUpdateProposal clientId. */
          public clientId: string;

          /** ClientUpdateProposal header. */
          public header?: google.protobuf.IAny | null;

          /**
           * Creates a new ClientUpdateProposal instance using the specified properties.
           * @param [properties] Properties to set
           * @returns ClientUpdateProposal instance
           */
          public static create(
            properties?: ibc.core.client.v1.IClientUpdateProposal,
          ): ibc.core.client.v1.ClientUpdateProposal;

          /**
           * Encodes the specified ClientUpdateProposal message. Does not implicitly {@link ibc.core.client.v1.ClientUpdateProposal.verify|verify} messages.
           * @param m ClientUpdateProposal message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.client.v1.IClientUpdateProposal,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a ClientUpdateProposal message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns ClientUpdateProposal
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.client.v1.ClientUpdateProposal;
        }

        /** Properties of a MsgCreateClient. */
        interface IMsgCreateClient {
          /** MsgCreateClient clientId */
          clientId?: string | null;

          /** MsgCreateClient clientState */
          clientState?: google.protobuf.IAny | null;

          /** MsgCreateClient consensusState */
          consensusState?: google.protobuf.IAny | null;

          /** MsgCreateClient signer */
          signer?: string | null;
        }

        /** Represents a MsgCreateClient. */
        class MsgCreateClient implements IMsgCreateClient {
          /**
           * Constructs a new MsgCreateClient.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.client.v1.IMsgCreateClient);

          /** MsgCreateClient clientId. */
          public clientId: string;

          /** MsgCreateClient clientState. */
          public clientState?: google.protobuf.IAny | null;

          /** MsgCreateClient consensusState. */
          public consensusState?: google.protobuf.IAny | null;

          /** MsgCreateClient signer. */
          public signer: string;

          /**
           * Creates a new MsgCreateClient instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MsgCreateClient instance
           */
          public static create(
            properties?: ibc.core.client.v1.IMsgCreateClient,
          ): ibc.core.client.v1.MsgCreateClient;

          /**
           * Encodes the specified MsgCreateClient message. Does not implicitly {@link ibc.core.client.v1.MsgCreateClient.verify|verify} messages.
           * @param m MsgCreateClient message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.client.v1.IMsgCreateClient,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a MsgCreateClient message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MsgCreateClient
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.client.v1.MsgCreateClient;
        }

        /** Properties of a MsgUpdateClient. */
        interface IMsgUpdateClient {
          /** MsgUpdateClient clientId */
          clientId?: string | null;

          /** MsgUpdateClient header */
          header?: google.protobuf.IAny | null;

          /** MsgUpdateClient signer */
          signer?: string | null;
        }

        /** Represents a MsgUpdateClient. */
        class MsgUpdateClient implements IMsgUpdateClient {
          /**
           * Constructs a new MsgUpdateClient.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.client.v1.IMsgUpdateClient);

          /** MsgUpdateClient clientId. */
          public clientId: string;

          /** MsgUpdateClient header. */
          public header?: google.protobuf.IAny | null;

          /** MsgUpdateClient signer. */
          public signer: string;

          /**
           * Creates a new MsgUpdateClient instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MsgUpdateClient instance
           */
          public static create(
            properties?: ibc.core.client.v1.IMsgUpdateClient,
          ): ibc.core.client.v1.MsgUpdateClient;

          /**
           * Encodes the specified MsgUpdateClient message. Does not implicitly {@link ibc.core.client.v1.MsgUpdateClient.verify|verify} messages.
           * @param m MsgUpdateClient message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.client.v1.IMsgUpdateClient,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a MsgUpdateClient message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MsgUpdateClient
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.client.v1.MsgUpdateClient;
        }

        /** Properties of a MsgUpgradeClient. */
        interface IMsgUpgradeClient {
          /** MsgUpgradeClient clientId */
          clientId?: string | null;

          /** MsgUpgradeClient clientState */
          clientState?: google.protobuf.IAny | null;

          /** MsgUpgradeClient proofUpgrade */
          proofUpgrade?: Uint8Array | null;

          /** MsgUpgradeClient signer */
          signer?: string | null;
        }

        /** Represents a MsgUpgradeClient. */
        class MsgUpgradeClient implements IMsgUpgradeClient {
          /**
           * Constructs a new MsgUpgradeClient.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.client.v1.IMsgUpgradeClient);

          /** MsgUpgradeClient clientId. */
          public clientId: string;

          /** MsgUpgradeClient clientState. */
          public clientState?: google.protobuf.IAny | null;

          /** MsgUpgradeClient proofUpgrade. */
          public proofUpgrade: Uint8Array;

          /** MsgUpgradeClient signer. */
          public signer: string;

          /**
           * Creates a new MsgUpgradeClient instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MsgUpgradeClient instance
           */
          public static create(
            properties?: ibc.core.client.v1.IMsgUpgradeClient,
          ): ibc.core.client.v1.MsgUpgradeClient;

          /**
           * Encodes the specified MsgUpgradeClient message. Does not implicitly {@link ibc.core.client.v1.MsgUpgradeClient.verify|verify} messages.
           * @param m MsgUpgradeClient message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.client.v1.IMsgUpgradeClient,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a MsgUpgradeClient message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MsgUpgradeClient
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.client.v1.MsgUpgradeClient;
        }

        /** Properties of a MsgSubmitMisbehaviour. */
        interface IMsgSubmitMisbehaviour {
          /** MsgSubmitMisbehaviour clientId */
          clientId?: string | null;

          /** MsgSubmitMisbehaviour misbehaviour */
          misbehaviour?: google.protobuf.IAny | null;

          /** MsgSubmitMisbehaviour signer */
          signer?: string | null;
        }

        /** Represents a MsgSubmitMisbehaviour. */
        class MsgSubmitMisbehaviour implements IMsgSubmitMisbehaviour {
          /**
           * Constructs a new MsgSubmitMisbehaviour.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.client.v1.IMsgSubmitMisbehaviour);

          /** MsgSubmitMisbehaviour clientId. */
          public clientId: string;

          /** MsgSubmitMisbehaviour misbehaviour. */
          public misbehaviour?: google.protobuf.IAny | null;

          /** MsgSubmitMisbehaviour signer. */
          public signer: string;

          /**
           * Creates a new MsgSubmitMisbehaviour instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MsgSubmitMisbehaviour instance
           */
          public static create(
            properties?: ibc.core.client.v1.IMsgSubmitMisbehaviour,
          ): ibc.core.client.v1.MsgSubmitMisbehaviour;

          /**
           * Encodes the specified MsgSubmitMisbehaviour message. Does not implicitly {@link ibc.core.client.v1.MsgSubmitMisbehaviour.verify|verify} messages.
           * @param m MsgSubmitMisbehaviour message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.client.v1.IMsgSubmitMisbehaviour,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a MsgSubmitMisbehaviour message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MsgSubmitMisbehaviour
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.client.v1.MsgSubmitMisbehaviour;
        }

        /** Properties of an Height. */
        interface IHeight {
          /** Height versionNumber */
          versionNumber?: Long | null;

          /** Height versionHeight */
          versionHeight?: Long | null;
        }

        /** Represents an Height. */
        class Height implements IHeight {
          /**
           * Constructs a new Height.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.client.v1.IHeight);

          /** Height versionNumber. */
          public versionNumber: Long;

          /** Height versionHeight. */
          public versionHeight: Long;

          /**
           * Creates a new Height instance using the specified properties.
           * @param [properties] Properties to set
           * @returns Height instance
           */
          public static create(properties?: ibc.core.client.v1.IHeight): ibc.core.client.v1.Height;

          /**
           * Encodes the specified Height message. Does not implicitly {@link ibc.core.client.v1.Height.verify|verify} messages.
           * @param m Height message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(m: ibc.core.client.v1.IHeight, w?: $protobuf.Writer): $protobuf.Writer;

          /**
           * Decodes an Height message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns Height
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(r: $protobuf.Reader | Uint8Array, l?: number): ibc.core.client.v1.Height;
        }
      }
    }

    /** Namespace commitment. */
    namespace commitment {
      /** Namespace v1. */
      namespace v1 {
        /** Properties of a MerkleRoot. */
        interface IMerkleRoot {
          /** MerkleRoot hash */
          hash?: Uint8Array | null;
        }

        /** Represents a MerkleRoot. */
        class MerkleRoot implements IMerkleRoot {
          /**
           * Constructs a new MerkleRoot.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.commitment.v1.IMerkleRoot);

          /** MerkleRoot hash. */
          public hash: Uint8Array;

          /**
           * Creates a new MerkleRoot instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MerkleRoot instance
           */
          public static create(
            properties?: ibc.core.commitment.v1.IMerkleRoot,
          ): ibc.core.commitment.v1.MerkleRoot;

          /**
           * Encodes the specified MerkleRoot message. Does not implicitly {@link ibc.core.commitment.v1.MerkleRoot.verify|verify} messages.
           * @param m MerkleRoot message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(m: ibc.core.commitment.v1.IMerkleRoot, w?: $protobuf.Writer): $protobuf.Writer;

          /**
           * Decodes a MerkleRoot message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MerkleRoot
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.commitment.v1.MerkleRoot;
        }

        /** Properties of a MerklePrefix. */
        interface IMerklePrefix {
          /** MerklePrefix keyPrefix */
          keyPrefix?: Uint8Array | null;
        }

        /** Represents a MerklePrefix. */
        class MerklePrefix implements IMerklePrefix {
          /**
           * Constructs a new MerklePrefix.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.commitment.v1.IMerklePrefix);

          /** MerklePrefix keyPrefix. */
          public keyPrefix: Uint8Array;

          /**
           * Creates a new MerklePrefix instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MerklePrefix instance
           */
          public static create(
            properties?: ibc.core.commitment.v1.IMerklePrefix,
          ): ibc.core.commitment.v1.MerklePrefix;

          /**
           * Encodes the specified MerklePrefix message. Does not implicitly {@link ibc.core.commitment.v1.MerklePrefix.verify|verify} messages.
           * @param m MerklePrefix message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.commitment.v1.IMerklePrefix,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a MerklePrefix message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MerklePrefix
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.commitment.v1.MerklePrefix;
        }

        /** Properties of a MerklePath. */
        interface IMerklePath {
          /** MerklePath keyPath */
          keyPath?: ibc.core.commitment.v1.IKeyPath | null;
        }

        /** Represents a MerklePath. */
        class MerklePath implements IMerklePath {
          /**
           * Constructs a new MerklePath.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.commitment.v1.IMerklePath);

          /** MerklePath keyPath. */
          public keyPath?: ibc.core.commitment.v1.IKeyPath | null;

          /**
           * Creates a new MerklePath instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MerklePath instance
           */
          public static create(
            properties?: ibc.core.commitment.v1.IMerklePath,
          ): ibc.core.commitment.v1.MerklePath;

          /**
           * Encodes the specified MerklePath message. Does not implicitly {@link ibc.core.commitment.v1.MerklePath.verify|verify} messages.
           * @param m MerklePath message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(m: ibc.core.commitment.v1.IMerklePath, w?: $protobuf.Writer): $protobuf.Writer;

          /**
           * Decodes a MerklePath message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MerklePath
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.commitment.v1.MerklePath;
        }

        /** Properties of a MerkleProof. */
        interface IMerkleProof {
          /** MerkleProof proof */
          proof?: tendermint.crypto.IProofOps | null;
        }

        /** Represents a MerkleProof. */
        class MerkleProof implements IMerkleProof {
          /**
           * Constructs a new MerkleProof.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.commitment.v1.IMerkleProof);

          /** MerkleProof proof. */
          public proof?: tendermint.crypto.IProofOps | null;

          /**
           * Creates a new MerkleProof instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MerkleProof instance
           */
          public static create(
            properties?: ibc.core.commitment.v1.IMerkleProof,
          ): ibc.core.commitment.v1.MerkleProof;

          /**
           * Encodes the specified MerkleProof message. Does not implicitly {@link ibc.core.commitment.v1.MerkleProof.verify|verify} messages.
           * @param m MerkleProof message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.commitment.v1.IMerkleProof,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a MerkleProof message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MerkleProof
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.commitment.v1.MerkleProof;
        }

        /** Properties of a KeyPath. */
        interface IKeyPath {
          /** KeyPath keys */
          keys?: ibc.core.commitment.v1.IKey[] | null;
        }

        /** Represents a KeyPath. */
        class KeyPath implements IKeyPath {
          /**
           * Constructs a new KeyPath.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.commitment.v1.IKeyPath);

          /** KeyPath keys. */
          public keys: ibc.core.commitment.v1.IKey[];

          /**
           * Creates a new KeyPath instance using the specified properties.
           * @param [properties] Properties to set
           * @returns KeyPath instance
           */
          public static create(properties?: ibc.core.commitment.v1.IKeyPath): ibc.core.commitment.v1.KeyPath;

          /**
           * Encodes the specified KeyPath message. Does not implicitly {@link ibc.core.commitment.v1.KeyPath.verify|verify} messages.
           * @param m KeyPath message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(m: ibc.core.commitment.v1.IKeyPath, w?: $protobuf.Writer): $protobuf.Writer;

          /**
           * Decodes a KeyPath message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns KeyPath
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(r: $protobuf.Reader | Uint8Array, l?: number): ibc.core.commitment.v1.KeyPath;
        }

        /** Properties of a Key. */
        interface IKey {
          /** Key name */
          name?: Uint8Array | null;

          /** Key enc */
          enc?: ibc.core.commitment.v1.KeyEncoding | null;
        }

        /** Represents a Key. */
        class Key implements IKey {
          /**
           * Constructs a new Key.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.commitment.v1.IKey);

          /** Key name. */
          public name: Uint8Array;

          /** Key enc. */
          public enc: ibc.core.commitment.v1.KeyEncoding;

          /**
           * Creates a new Key instance using the specified properties.
           * @param [properties] Properties to set
           * @returns Key instance
           */
          public static create(properties?: ibc.core.commitment.v1.IKey): ibc.core.commitment.v1.Key;

          /**
           * Encodes the specified Key message. Does not implicitly {@link ibc.core.commitment.v1.Key.verify|verify} messages.
           * @param m Key message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(m: ibc.core.commitment.v1.IKey, w?: $protobuf.Writer): $protobuf.Writer;

          /**
           * Decodes a Key message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns Key
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(r: $protobuf.Reader | Uint8Array, l?: number): ibc.core.commitment.v1.Key;
        }

        /** KeyEncoding enum. */
        enum KeyEncoding {
          KEY_ENCODING_URL_UNSPECIFIED = 0,
          KEY_ENCODING_HEX = 1,
        }
      }
    }

    /** Namespace connection. */
    namespace connection {
      /** Namespace v1. */
      namespace v1 {
        /** Properties of a MsgConnectionOpenInit. */
        interface IMsgConnectionOpenInit {
          /** MsgConnectionOpenInit clientId */
          clientId?: string | null;

          /** MsgConnectionOpenInit connectionId */
          connectionId?: string | null;

          /** MsgConnectionOpenInit counterparty */
          counterparty?: ibc.core.connection.v1.ICounterparty | null;

          /** MsgConnectionOpenInit version */
          version?: string | null;

          /** MsgConnectionOpenInit signer */
          signer?: string | null;
        }

        /** Represents a MsgConnectionOpenInit. */
        class MsgConnectionOpenInit implements IMsgConnectionOpenInit {
          /**
           * Constructs a new MsgConnectionOpenInit.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.connection.v1.IMsgConnectionOpenInit);

          /** MsgConnectionOpenInit clientId. */
          public clientId: string;

          /** MsgConnectionOpenInit connectionId. */
          public connectionId: string;

          /** MsgConnectionOpenInit counterparty. */
          public counterparty?: ibc.core.connection.v1.ICounterparty | null;

          /** MsgConnectionOpenInit version. */
          public version: string;

          /** MsgConnectionOpenInit signer. */
          public signer: string;

          /**
           * Creates a new MsgConnectionOpenInit instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MsgConnectionOpenInit instance
           */
          public static create(
            properties?: ibc.core.connection.v1.IMsgConnectionOpenInit,
          ): ibc.core.connection.v1.MsgConnectionOpenInit;

          /**
           * Encodes the specified MsgConnectionOpenInit message. Does not implicitly {@link ibc.core.connection.v1.MsgConnectionOpenInit.verify|verify} messages.
           * @param m MsgConnectionOpenInit message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.connection.v1.IMsgConnectionOpenInit,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a MsgConnectionOpenInit message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MsgConnectionOpenInit
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.connection.v1.MsgConnectionOpenInit;
        }

        /** Properties of a MsgConnectionOpenTry. */
        interface IMsgConnectionOpenTry {
          /** MsgConnectionOpenTry clientId */
          clientId?: string | null;

          /** MsgConnectionOpenTry connectionId */
          connectionId?: string | null;

          /** MsgConnectionOpenTry provedId */
          provedId?: string | null;

          /** MsgConnectionOpenTry clientState */
          clientState?: google.protobuf.IAny | null;

          /** MsgConnectionOpenTry counterparty */
          counterparty?: ibc.core.connection.v1.ICounterparty | null;

          /** MsgConnectionOpenTry counterpartyVersions */
          counterpartyVersions?: string[] | null;

          /** MsgConnectionOpenTry proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgConnectionOpenTry proofInit */
          proofInit?: Uint8Array | null;

          /** MsgConnectionOpenTry proofClient */
          proofClient?: Uint8Array | null;

          /** MsgConnectionOpenTry proofConsensus */
          proofConsensus?: Uint8Array | null;

          /** MsgConnectionOpenTry consensusHeight */
          consensusHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgConnectionOpenTry signer */
          signer?: string | null;
        }

        /** Represents a MsgConnectionOpenTry. */
        class MsgConnectionOpenTry implements IMsgConnectionOpenTry {
          /**
           * Constructs a new MsgConnectionOpenTry.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.connection.v1.IMsgConnectionOpenTry);

          /** MsgConnectionOpenTry clientId. */
          public clientId: string;

          /** MsgConnectionOpenTry connectionId. */
          public connectionId: string;

          /** MsgConnectionOpenTry provedId. */
          public provedId: string;

          /** MsgConnectionOpenTry clientState. */
          public clientState?: google.protobuf.IAny | null;

          /** MsgConnectionOpenTry counterparty. */
          public counterparty?: ibc.core.connection.v1.ICounterparty | null;

          /** MsgConnectionOpenTry counterpartyVersions. */
          public counterpartyVersions: string[];

          /** MsgConnectionOpenTry proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgConnectionOpenTry proofInit. */
          public proofInit: Uint8Array;

          /** MsgConnectionOpenTry proofClient. */
          public proofClient: Uint8Array;

          /** MsgConnectionOpenTry proofConsensus. */
          public proofConsensus: Uint8Array;

          /** MsgConnectionOpenTry consensusHeight. */
          public consensusHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgConnectionOpenTry signer. */
          public signer: string;

          /**
           * Creates a new MsgConnectionOpenTry instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MsgConnectionOpenTry instance
           */
          public static create(
            properties?: ibc.core.connection.v1.IMsgConnectionOpenTry,
          ): ibc.core.connection.v1.MsgConnectionOpenTry;

          /**
           * Encodes the specified MsgConnectionOpenTry message. Does not implicitly {@link ibc.core.connection.v1.MsgConnectionOpenTry.verify|verify} messages.
           * @param m MsgConnectionOpenTry message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.connection.v1.IMsgConnectionOpenTry,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a MsgConnectionOpenTry message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MsgConnectionOpenTry
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.connection.v1.MsgConnectionOpenTry;
        }

        /** Properties of a MsgConnectionOpenAck. */
        interface IMsgConnectionOpenAck {
          /** MsgConnectionOpenAck connectionId */
          connectionId?: string | null;

          /** MsgConnectionOpenAck counterpartyConnectionId */
          counterpartyConnectionId?: string | null;

          /** MsgConnectionOpenAck version */
          version?: string | null;

          /** MsgConnectionOpenAck clientState */
          clientState?: google.protobuf.IAny | null;

          /** MsgConnectionOpenAck proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgConnectionOpenAck proofTry */
          proofTry?: Uint8Array | null;

          /** MsgConnectionOpenAck proofClient */
          proofClient?: Uint8Array | null;

          /** MsgConnectionOpenAck proofConsensus */
          proofConsensus?: Uint8Array | null;

          /** MsgConnectionOpenAck consensusHeight */
          consensusHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgConnectionOpenAck signer */
          signer?: string | null;
        }

        /** Represents a MsgConnectionOpenAck. */
        class MsgConnectionOpenAck implements IMsgConnectionOpenAck {
          /**
           * Constructs a new MsgConnectionOpenAck.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.connection.v1.IMsgConnectionOpenAck);

          /** MsgConnectionOpenAck connectionId. */
          public connectionId: string;

          /** MsgConnectionOpenAck counterpartyConnectionId. */
          public counterpartyConnectionId: string;

          /** MsgConnectionOpenAck version. */
          public version: string;

          /** MsgConnectionOpenAck clientState. */
          public clientState?: google.protobuf.IAny | null;

          /** MsgConnectionOpenAck proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgConnectionOpenAck proofTry. */
          public proofTry: Uint8Array;

          /** MsgConnectionOpenAck proofClient. */
          public proofClient: Uint8Array;

          /** MsgConnectionOpenAck proofConsensus. */
          public proofConsensus: Uint8Array;

          /** MsgConnectionOpenAck consensusHeight. */
          public consensusHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgConnectionOpenAck signer. */
          public signer: string;

          /**
           * Creates a new MsgConnectionOpenAck instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MsgConnectionOpenAck instance
           */
          public static create(
            properties?: ibc.core.connection.v1.IMsgConnectionOpenAck,
          ): ibc.core.connection.v1.MsgConnectionOpenAck;

          /**
           * Encodes the specified MsgConnectionOpenAck message. Does not implicitly {@link ibc.core.connection.v1.MsgConnectionOpenAck.verify|verify} messages.
           * @param m MsgConnectionOpenAck message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.connection.v1.IMsgConnectionOpenAck,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a MsgConnectionOpenAck message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MsgConnectionOpenAck
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.connection.v1.MsgConnectionOpenAck;
        }

        /** Properties of a MsgConnectionOpenConfirm. */
        interface IMsgConnectionOpenConfirm {
          /** MsgConnectionOpenConfirm connectionId */
          connectionId?: string | null;

          /** MsgConnectionOpenConfirm proofAck */
          proofAck?: Uint8Array | null;

          /** MsgConnectionOpenConfirm proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgConnectionOpenConfirm signer */
          signer?: string | null;
        }

        /** Represents a MsgConnectionOpenConfirm. */
        class MsgConnectionOpenConfirm implements IMsgConnectionOpenConfirm {
          /**
           * Constructs a new MsgConnectionOpenConfirm.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.connection.v1.IMsgConnectionOpenConfirm);

          /** MsgConnectionOpenConfirm connectionId. */
          public connectionId: string;

          /** MsgConnectionOpenConfirm proofAck. */
          public proofAck: Uint8Array;

          /** MsgConnectionOpenConfirm proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /** MsgConnectionOpenConfirm signer. */
          public signer: string;

          /**
           * Creates a new MsgConnectionOpenConfirm instance using the specified properties.
           * @param [properties] Properties to set
           * @returns MsgConnectionOpenConfirm instance
           */
          public static create(
            properties?: ibc.core.connection.v1.IMsgConnectionOpenConfirm,
          ): ibc.core.connection.v1.MsgConnectionOpenConfirm;

          /**
           * Encodes the specified MsgConnectionOpenConfirm message. Does not implicitly {@link ibc.core.connection.v1.MsgConnectionOpenConfirm.verify|verify} messages.
           * @param m MsgConnectionOpenConfirm message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.connection.v1.IMsgConnectionOpenConfirm,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a MsgConnectionOpenConfirm message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns MsgConnectionOpenConfirm
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.connection.v1.MsgConnectionOpenConfirm;
        }

        /** Properties of a ConnectionEnd. */
        interface IConnectionEnd {
          /** ConnectionEnd clientId */
          clientId?: string | null;

          /** ConnectionEnd versions */
          versions?: string[] | null;

          /** ConnectionEnd state */
          state?: ibc.core.connection.v1.State | null;

          /** ConnectionEnd counterparty */
          counterparty?: ibc.core.connection.v1.ICounterparty | null;
        }

        /** Represents a ConnectionEnd. */
        class ConnectionEnd implements IConnectionEnd {
          /**
           * Constructs a new ConnectionEnd.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.connection.v1.IConnectionEnd);

          /** ConnectionEnd clientId. */
          public clientId: string;

          /** ConnectionEnd versions. */
          public versions: string[];

          /** ConnectionEnd state. */
          public state: ibc.core.connection.v1.State;

          /** ConnectionEnd counterparty. */
          public counterparty?: ibc.core.connection.v1.ICounterparty | null;

          /**
           * Creates a new ConnectionEnd instance using the specified properties.
           * @param [properties] Properties to set
           * @returns ConnectionEnd instance
           */
          public static create(
            properties?: ibc.core.connection.v1.IConnectionEnd,
          ): ibc.core.connection.v1.ConnectionEnd;

          /**
           * Encodes the specified ConnectionEnd message. Does not implicitly {@link ibc.core.connection.v1.ConnectionEnd.verify|verify} messages.
           * @param m ConnectionEnd message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.connection.v1.IConnectionEnd,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a ConnectionEnd message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns ConnectionEnd
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.connection.v1.ConnectionEnd;
        }

        /** Properties of an IdentifiedConnection. */
        interface IIdentifiedConnection {
          /** IdentifiedConnection id */
          id?: string | null;

          /** IdentifiedConnection clientId */
          clientId?: string | null;

          /** IdentifiedConnection versions */
          versions?: string[] | null;

          /** IdentifiedConnection state */
          state?: ibc.core.connection.v1.State | null;

          /** IdentifiedConnection counterparty */
          counterparty?: ibc.core.connection.v1.ICounterparty | null;
        }

        /** Represents an IdentifiedConnection. */
        class IdentifiedConnection implements IIdentifiedConnection {
          /**
           * Constructs a new IdentifiedConnection.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.connection.v1.IIdentifiedConnection);

          /** IdentifiedConnection id. */
          public id: string;

          /** IdentifiedConnection clientId. */
          public clientId: string;

          /** IdentifiedConnection versions. */
          public versions: string[];

          /** IdentifiedConnection state. */
          public state: ibc.core.connection.v1.State;

          /** IdentifiedConnection counterparty. */
          public counterparty?: ibc.core.connection.v1.ICounterparty | null;

          /**
           * Creates a new IdentifiedConnection instance using the specified properties.
           * @param [properties] Properties to set
           * @returns IdentifiedConnection instance
           */
          public static create(
            properties?: ibc.core.connection.v1.IIdentifiedConnection,
          ): ibc.core.connection.v1.IdentifiedConnection;

          /**
           * Encodes the specified IdentifiedConnection message. Does not implicitly {@link ibc.core.connection.v1.IdentifiedConnection.verify|verify} messages.
           * @param m IdentifiedConnection message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.connection.v1.IIdentifiedConnection,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes an IdentifiedConnection message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns IdentifiedConnection
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.connection.v1.IdentifiedConnection;
        }

        /** State enum. */
        enum State {
          STATE_UNINITIALIZED_UNSPECIFIED = 0,
          STATE_INIT = 1,
          STATE_TRYOPEN = 2,
          STATE_OPEN = 3,
        }

        /** Properties of a Counterparty. */
        interface ICounterparty {
          /** Counterparty clientId */
          clientId?: string | null;

          /** Counterparty connectionId */
          connectionId?: string | null;

          /** Counterparty prefix */
          prefix?: ibc.core.commitment.v1.IMerklePrefix | null;
        }

        /** Represents a Counterparty. */
        class Counterparty implements ICounterparty {
          /**
           * Constructs a new Counterparty.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.connection.v1.ICounterparty);

          /** Counterparty clientId. */
          public clientId: string;

          /** Counterparty connectionId. */
          public connectionId: string;

          /** Counterparty prefix. */
          public prefix?: ibc.core.commitment.v1.IMerklePrefix | null;

          /**
           * Creates a new Counterparty instance using the specified properties.
           * @param [properties] Properties to set
           * @returns Counterparty instance
           */
          public static create(
            properties?: ibc.core.connection.v1.ICounterparty,
          ): ibc.core.connection.v1.Counterparty;

          /**
           * Encodes the specified Counterparty message. Does not implicitly {@link ibc.core.connection.v1.Counterparty.verify|verify} messages.
           * @param m Counterparty message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.connection.v1.ICounterparty,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a Counterparty message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns Counterparty
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.connection.v1.Counterparty;
        }

        /** Properties of a ClientPaths. */
        interface IClientPaths {
          /** ClientPaths paths */
          paths?: string[] | null;
        }

        /** Represents a ClientPaths. */
        class ClientPaths implements IClientPaths {
          /**
           * Constructs a new ClientPaths.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.connection.v1.IClientPaths);

          /** ClientPaths paths. */
          public paths: string[];

          /**
           * Creates a new ClientPaths instance using the specified properties.
           * @param [properties] Properties to set
           * @returns ClientPaths instance
           */
          public static create(
            properties?: ibc.core.connection.v1.IClientPaths,
          ): ibc.core.connection.v1.ClientPaths;

          /**
           * Encodes the specified ClientPaths message. Does not implicitly {@link ibc.core.connection.v1.ClientPaths.verify|verify} messages.
           * @param m ClientPaths message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.connection.v1.IClientPaths,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a ClientPaths message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns ClientPaths
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.connection.v1.ClientPaths;
        }

        /** Properties of a ConnectionPaths. */
        interface IConnectionPaths {
          /** ConnectionPaths clientId */
          clientId?: string | null;

          /** ConnectionPaths paths */
          paths?: string[] | null;
        }

        /** Represents a ConnectionPaths. */
        class ConnectionPaths implements IConnectionPaths {
          /**
           * Constructs a new ConnectionPaths.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.connection.v1.IConnectionPaths);

          /** ConnectionPaths clientId. */
          public clientId: string;

          /** ConnectionPaths paths. */
          public paths: string[];

          /**
           * Creates a new ConnectionPaths instance using the specified properties.
           * @param [properties] Properties to set
           * @returns ConnectionPaths instance
           */
          public static create(
            properties?: ibc.core.connection.v1.IConnectionPaths,
          ): ibc.core.connection.v1.ConnectionPaths;

          /**
           * Encodes the specified ConnectionPaths message. Does not implicitly {@link ibc.core.connection.v1.ConnectionPaths.verify|verify} messages.
           * @param m ConnectionPaths message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.connection.v1.IConnectionPaths,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a ConnectionPaths message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns ConnectionPaths
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.connection.v1.ConnectionPaths;
        }

        /** Properties of a Version. */
        interface IVersion {
          /** Version identifier */
          identifier?: string | null;

          /** Version features */
          features?: string[] | null;
        }

        /** Represents a Version. */
        class Version implements IVersion {
          /**
           * Constructs a new Version.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.connection.v1.IVersion);

          /** Version identifier. */
          public identifier: string;

          /** Version features. */
          public features: string[];

          /**
           * Creates a new Version instance using the specified properties.
           * @param [properties] Properties to set
           * @returns Version instance
           */
          public static create(properties?: ibc.core.connection.v1.IVersion): ibc.core.connection.v1.Version;

          /**
           * Encodes the specified Version message. Does not implicitly {@link ibc.core.connection.v1.Version.verify|verify} messages.
           * @param m Version message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(m: ibc.core.connection.v1.IVersion, w?: $protobuf.Writer): $protobuf.Writer;

          /**
           * Decodes a Version message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns Version
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(r: $protobuf.Reader | Uint8Array, l?: number): ibc.core.connection.v1.Version;
        }

        /** Represents a Query */
        class Query extends $protobuf.rpc.Service {
          /**
           * Constructs a new Query service.
           * @param rpcImpl RPC implementation
           * @param [requestDelimited=false] Whether requests are length-delimited
           * @param [responseDelimited=false] Whether responses are length-delimited
           */
          constructor(rpcImpl: $protobuf.RPCImpl, requestDelimited?: boolean, responseDelimited?: boolean);

          /**
           * Creates new Query service using the specified rpc implementation.
           * @param rpcImpl RPC implementation
           * @param [requestDelimited=false] Whether requests are length-delimited
           * @param [responseDelimited=false] Whether responses are length-delimited
           * @returns RPC service. Useful where requests and/or responses are streamed.
           */
          public static create(
            rpcImpl: $protobuf.RPCImpl,
            requestDelimited?: boolean,
            responseDelimited?: boolean,
          ): Query;

          /**
           * Calls Connection.
           * @param request QueryConnectionRequest message or plain object
           * @param callback Node-style callback called with the error, if any, and QueryConnectionResponse
           */
          public connection(
            request: ibc.core.connection.v1.IQueryConnectionRequest,
            callback: ibc.core.connection.v1.Query.ConnectionCallback,
          ): void;

          /**
           * Calls Connection.
           * @param request QueryConnectionRequest message or plain object
           * @returns Promise
           */
          public connection(
            request: ibc.core.connection.v1.IQueryConnectionRequest,
          ): Promise<ibc.core.connection.v1.QueryConnectionResponse>;

          /**
           * Calls Connections.
           * @param request QueryConnectionsRequest message or plain object
           * @param callback Node-style callback called with the error, if any, and QueryConnectionsResponse
           */
          public connections(
            request: ibc.core.connection.v1.IQueryConnectionsRequest,
            callback: ibc.core.connection.v1.Query.ConnectionsCallback,
          ): void;

          /**
           * Calls Connections.
           * @param request QueryConnectionsRequest message or plain object
           * @returns Promise
           */
          public connections(
            request: ibc.core.connection.v1.IQueryConnectionsRequest,
          ): Promise<ibc.core.connection.v1.QueryConnectionsResponse>;

          /**
           * Calls ClientConnections.
           * @param request QueryClientConnectionsRequest message or plain object
           * @param callback Node-style callback called with the error, if any, and QueryClientConnectionsResponse
           */
          public clientConnections(
            request: ibc.core.connection.v1.IQueryClientConnectionsRequest,
            callback: ibc.core.connection.v1.Query.ClientConnectionsCallback,
          ): void;

          /**
           * Calls ClientConnections.
           * @param request QueryClientConnectionsRequest message or plain object
           * @returns Promise
           */
          public clientConnections(
            request: ibc.core.connection.v1.IQueryClientConnectionsRequest,
          ): Promise<ibc.core.connection.v1.QueryClientConnectionsResponse>;

          /**
           * Calls ConnectionClientState.
           * @param request QueryConnectionClientStateRequest message or plain object
           * @param callback Node-style callback called with the error, if any, and QueryConnectionClientStateResponse
           */
          public connectionClientState(
            request: ibc.core.connection.v1.IQueryConnectionClientStateRequest,
            callback: ibc.core.connection.v1.Query.ConnectionClientStateCallback,
          ): void;

          /**
           * Calls ConnectionClientState.
           * @param request QueryConnectionClientStateRequest message or plain object
           * @returns Promise
           */
          public connectionClientState(
            request: ibc.core.connection.v1.IQueryConnectionClientStateRequest,
          ): Promise<ibc.core.connection.v1.QueryConnectionClientStateResponse>;

          /**
           * Calls ConnectionConsensusState.
           * @param request QueryConnectionConsensusStateRequest message or plain object
           * @param callback Node-style callback called with the error, if any, and QueryConnectionConsensusStateResponse
           */
          public connectionConsensusState(
            request: ibc.core.connection.v1.IQueryConnectionConsensusStateRequest,
            callback: ibc.core.connection.v1.Query.ConnectionConsensusStateCallback,
          ): void;

          /**
           * Calls ConnectionConsensusState.
           * @param request QueryConnectionConsensusStateRequest message or plain object
           * @returns Promise
           */
          public connectionConsensusState(
            request: ibc.core.connection.v1.IQueryConnectionConsensusStateRequest,
          ): Promise<ibc.core.connection.v1.QueryConnectionConsensusStateResponse>;
        }

        namespace Query {
          /**
           * Callback as used by {@link ibc.core.connection.v1.Query#connection}.
           * @param error Error, if any
           * @param [response] QueryConnectionResponse
           */
          type ConnectionCallback = (
            error: Error | null,
            response?: ibc.core.connection.v1.QueryConnectionResponse,
          ) => void;

          /**
           * Callback as used by {@link ibc.core.connection.v1.Query#connections}.
           * @param error Error, if any
           * @param [response] QueryConnectionsResponse
           */
          type ConnectionsCallback = (
            error: Error | null,
            response?: ibc.core.connection.v1.QueryConnectionsResponse,
          ) => void;

          /**
           * Callback as used by {@link ibc.core.connection.v1.Query#clientConnections}.
           * @param error Error, if any
           * @param [response] QueryClientConnectionsResponse
           */
          type ClientConnectionsCallback = (
            error: Error | null,
            response?: ibc.core.connection.v1.QueryClientConnectionsResponse,
          ) => void;

          /**
           * Callback as used by {@link ibc.core.connection.v1.Query#connectionClientState}.
           * @param error Error, if any
           * @param [response] QueryConnectionClientStateResponse
           */
          type ConnectionClientStateCallback = (
            error: Error | null,
            response?: ibc.core.connection.v1.QueryConnectionClientStateResponse,
          ) => void;

          /**
           * Callback as used by {@link ibc.core.connection.v1.Query#connectionConsensusState}.
           * @param error Error, if any
           * @param [response] QueryConnectionConsensusStateResponse
           */
          type ConnectionConsensusStateCallback = (
            error: Error | null,
            response?: ibc.core.connection.v1.QueryConnectionConsensusStateResponse,
          ) => void;
        }

        /** Properties of a QueryConnectionRequest. */
        interface IQueryConnectionRequest {
          /** QueryConnectionRequest connectionId */
          connectionId?: string | null;
        }

        /** Represents a QueryConnectionRequest. */
        class QueryConnectionRequest implements IQueryConnectionRequest {
          /**
           * Constructs a new QueryConnectionRequest.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.connection.v1.IQueryConnectionRequest);

          /** QueryConnectionRequest connectionId. */
          public connectionId: string;

          /**
           * Creates a new QueryConnectionRequest instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryConnectionRequest instance
           */
          public static create(
            properties?: ibc.core.connection.v1.IQueryConnectionRequest,
          ): ibc.core.connection.v1.QueryConnectionRequest;

          /**
           * Encodes the specified QueryConnectionRequest message. Does not implicitly {@link ibc.core.connection.v1.QueryConnectionRequest.verify|verify} messages.
           * @param m QueryConnectionRequest message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.connection.v1.IQueryConnectionRequest,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryConnectionRequest message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryConnectionRequest
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.connection.v1.QueryConnectionRequest;
        }

        /** Properties of a QueryConnectionResponse. */
        interface IQueryConnectionResponse {
          /** QueryConnectionResponse connection */
          connection?: ibc.core.connection.v1.IConnectionEnd | null;

          /** QueryConnectionResponse proof */
          proof?: Uint8Array | null;

          /** QueryConnectionResponse proofPath */
          proofPath?: string | null;

          /** QueryConnectionResponse proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;
        }

        /** Represents a QueryConnectionResponse. */
        class QueryConnectionResponse implements IQueryConnectionResponse {
          /**
           * Constructs a new QueryConnectionResponse.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.connection.v1.IQueryConnectionResponse);

          /** QueryConnectionResponse connection. */
          public connection?: ibc.core.connection.v1.IConnectionEnd | null;

          /** QueryConnectionResponse proof. */
          public proof: Uint8Array;

          /** QueryConnectionResponse proofPath. */
          public proofPath: string;

          /** QueryConnectionResponse proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /**
           * Creates a new QueryConnectionResponse instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryConnectionResponse instance
           */
          public static create(
            properties?: ibc.core.connection.v1.IQueryConnectionResponse,
          ): ibc.core.connection.v1.QueryConnectionResponse;

          /**
           * Encodes the specified QueryConnectionResponse message. Does not implicitly {@link ibc.core.connection.v1.QueryConnectionResponse.verify|verify} messages.
           * @param m QueryConnectionResponse message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.connection.v1.IQueryConnectionResponse,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryConnectionResponse message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryConnectionResponse
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.connection.v1.QueryConnectionResponse;
        }

        /** Properties of a QueryConnectionsRequest. */
        interface IQueryConnectionsRequest {
          /** QueryConnectionsRequest pagination */
          pagination?: cosmos.base.query.v1beta1.IPageRequest | null;
        }

        /** Represents a QueryConnectionsRequest. */
        class QueryConnectionsRequest implements IQueryConnectionsRequest {
          /**
           * Constructs a new QueryConnectionsRequest.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.connection.v1.IQueryConnectionsRequest);

          /** QueryConnectionsRequest pagination. */
          public pagination?: cosmos.base.query.v1beta1.IPageRequest | null;

          /**
           * Creates a new QueryConnectionsRequest instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryConnectionsRequest instance
           */
          public static create(
            properties?: ibc.core.connection.v1.IQueryConnectionsRequest,
          ): ibc.core.connection.v1.QueryConnectionsRequest;

          /**
           * Encodes the specified QueryConnectionsRequest message. Does not implicitly {@link ibc.core.connection.v1.QueryConnectionsRequest.verify|verify} messages.
           * @param m QueryConnectionsRequest message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.connection.v1.IQueryConnectionsRequest,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryConnectionsRequest message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryConnectionsRequest
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.connection.v1.QueryConnectionsRequest;
        }

        /** Properties of a QueryConnectionsResponse. */
        interface IQueryConnectionsResponse {
          /** QueryConnectionsResponse connections */
          connections?: ibc.core.connection.v1.IIdentifiedConnection[] | null;

          /** QueryConnectionsResponse pagination */
          pagination?: cosmos.base.query.v1beta1.IPageResponse | null;

          /** QueryConnectionsResponse height */
          height?: ibc.core.client.v1.IHeight | null;
        }

        /** Represents a QueryConnectionsResponse. */
        class QueryConnectionsResponse implements IQueryConnectionsResponse {
          /**
           * Constructs a new QueryConnectionsResponse.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.connection.v1.IQueryConnectionsResponse);

          /** QueryConnectionsResponse connections. */
          public connections: ibc.core.connection.v1.IIdentifiedConnection[];

          /** QueryConnectionsResponse pagination. */
          public pagination?: cosmos.base.query.v1beta1.IPageResponse | null;

          /** QueryConnectionsResponse height. */
          public height?: ibc.core.client.v1.IHeight | null;

          /**
           * Creates a new QueryConnectionsResponse instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryConnectionsResponse instance
           */
          public static create(
            properties?: ibc.core.connection.v1.IQueryConnectionsResponse,
          ): ibc.core.connection.v1.QueryConnectionsResponse;

          /**
           * Encodes the specified QueryConnectionsResponse message. Does not implicitly {@link ibc.core.connection.v1.QueryConnectionsResponse.verify|verify} messages.
           * @param m QueryConnectionsResponse message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.connection.v1.IQueryConnectionsResponse,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryConnectionsResponse message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryConnectionsResponse
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.connection.v1.QueryConnectionsResponse;
        }

        /** Properties of a QueryClientConnectionsRequest. */
        interface IQueryClientConnectionsRequest {
          /** QueryClientConnectionsRequest clientId */
          clientId?: string | null;
        }

        /** Represents a QueryClientConnectionsRequest. */
        class QueryClientConnectionsRequest implements IQueryClientConnectionsRequest {
          /**
           * Constructs a new QueryClientConnectionsRequest.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.connection.v1.IQueryClientConnectionsRequest);

          /** QueryClientConnectionsRequest clientId. */
          public clientId: string;

          /**
           * Creates a new QueryClientConnectionsRequest instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryClientConnectionsRequest instance
           */
          public static create(
            properties?: ibc.core.connection.v1.IQueryClientConnectionsRequest,
          ): ibc.core.connection.v1.QueryClientConnectionsRequest;

          /**
           * Encodes the specified QueryClientConnectionsRequest message. Does not implicitly {@link ibc.core.connection.v1.QueryClientConnectionsRequest.verify|verify} messages.
           * @param m QueryClientConnectionsRequest message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.connection.v1.IQueryClientConnectionsRequest,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryClientConnectionsRequest message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryClientConnectionsRequest
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.connection.v1.QueryClientConnectionsRequest;
        }

        /** Properties of a QueryClientConnectionsResponse. */
        interface IQueryClientConnectionsResponse {
          /** QueryClientConnectionsResponse connectionPaths */
          connectionPaths?: string[] | null;

          /** QueryClientConnectionsResponse proof */
          proof?: Uint8Array | null;

          /** QueryClientConnectionsResponse proofPath */
          proofPath?: string | null;

          /** QueryClientConnectionsResponse proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;
        }

        /** Represents a QueryClientConnectionsResponse. */
        class QueryClientConnectionsResponse implements IQueryClientConnectionsResponse {
          /**
           * Constructs a new QueryClientConnectionsResponse.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.connection.v1.IQueryClientConnectionsResponse);

          /** QueryClientConnectionsResponse connectionPaths. */
          public connectionPaths: string[];

          /** QueryClientConnectionsResponse proof. */
          public proof: Uint8Array;

          /** QueryClientConnectionsResponse proofPath. */
          public proofPath: string;

          /** QueryClientConnectionsResponse proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /**
           * Creates a new QueryClientConnectionsResponse instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryClientConnectionsResponse instance
           */
          public static create(
            properties?: ibc.core.connection.v1.IQueryClientConnectionsResponse,
          ): ibc.core.connection.v1.QueryClientConnectionsResponse;

          /**
           * Encodes the specified QueryClientConnectionsResponse message. Does not implicitly {@link ibc.core.connection.v1.QueryClientConnectionsResponse.verify|verify} messages.
           * @param m QueryClientConnectionsResponse message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.connection.v1.IQueryClientConnectionsResponse,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryClientConnectionsResponse message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryClientConnectionsResponse
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.connection.v1.QueryClientConnectionsResponse;
        }

        /** Properties of a QueryConnectionClientStateRequest. */
        interface IQueryConnectionClientStateRequest {
          /** QueryConnectionClientStateRequest connectionId */
          connectionId?: string | null;
        }

        /** Represents a QueryConnectionClientStateRequest. */
        class QueryConnectionClientStateRequest implements IQueryConnectionClientStateRequest {
          /**
           * Constructs a new QueryConnectionClientStateRequest.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.connection.v1.IQueryConnectionClientStateRequest);

          /** QueryConnectionClientStateRequest connectionId. */
          public connectionId: string;

          /**
           * Creates a new QueryConnectionClientStateRequest instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryConnectionClientStateRequest instance
           */
          public static create(
            properties?: ibc.core.connection.v1.IQueryConnectionClientStateRequest,
          ): ibc.core.connection.v1.QueryConnectionClientStateRequest;

          /**
           * Encodes the specified QueryConnectionClientStateRequest message. Does not implicitly {@link ibc.core.connection.v1.QueryConnectionClientStateRequest.verify|verify} messages.
           * @param m QueryConnectionClientStateRequest message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.connection.v1.IQueryConnectionClientStateRequest,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryConnectionClientStateRequest message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryConnectionClientStateRequest
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.connection.v1.QueryConnectionClientStateRequest;
        }

        /** Properties of a QueryConnectionClientStateResponse. */
        interface IQueryConnectionClientStateResponse {
          /** QueryConnectionClientStateResponse identifiedClientState */
          identifiedClientState?: ibc.core.client.v1.IIdentifiedClientState | null;

          /** QueryConnectionClientStateResponse proof */
          proof?: Uint8Array | null;

          /** QueryConnectionClientStateResponse proofPath */
          proofPath?: string | null;

          /** QueryConnectionClientStateResponse proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;
        }

        /** Represents a QueryConnectionClientStateResponse. */
        class QueryConnectionClientStateResponse implements IQueryConnectionClientStateResponse {
          /**
           * Constructs a new QueryConnectionClientStateResponse.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.connection.v1.IQueryConnectionClientStateResponse);

          /** QueryConnectionClientStateResponse identifiedClientState. */
          public identifiedClientState?: ibc.core.client.v1.IIdentifiedClientState | null;

          /** QueryConnectionClientStateResponse proof. */
          public proof: Uint8Array;

          /** QueryConnectionClientStateResponse proofPath. */
          public proofPath: string;

          /** QueryConnectionClientStateResponse proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /**
           * Creates a new QueryConnectionClientStateResponse instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryConnectionClientStateResponse instance
           */
          public static create(
            properties?: ibc.core.connection.v1.IQueryConnectionClientStateResponse,
          ): ibc.core.connection.v1.QueryConnectionClientStateResponse;

          /**
           * Encodes the specified QueryConnectionClientStateResponse message. Does not implicitly {@link ibc.core.connection.v1.QueryConnectionClientStateResponse.verify|verify} messages.
           * @param m QueryConnectionClientStateResponse message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.connection.v1.IQueryConnectionClientStateResponse,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryConnectionClientStateResponse message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryConnectionClientStateResponse
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.connection.v1.QueryConnectionClientStateResponse;
        }

        /** Properties of a QueryConnectionConsensusStateRequest. */
        interface IQueryConnectionConsensusStateRequest {
          /** QueryConnectionConsensusStateRequest connectionId */
          connectionId?: string | null;

          /** QueryConnectionConsensusStateRequest versionNumber */
          versionNumber?: Long | null;

          /** QueryConnectionConsensusStateRequest versionHeight */
          versionHeight?: Long | null;
        }

        /** Represents a QueryConnectionConsensusStateRequest. */
        class QueryConnectionConsensusStateRequest implements IQueryConnectionConsensusStateRequest {
          /**
           * Constructs a new QueryConnectionConsensusStateRequest.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.connection.v1.IQueryConnectionConsensusStateRequest);

          /** QueryConnectionConsensusStateRequest connectionId. */
          public connectionId: string;

          /** QueryConnectionConsensusStateRequest versionNumber. */
          public versionNumber: Long;

          /** QueryConnectionConsensusStateRequest versionHeight. */
          public versionHeight: Long;

          /**
           * Creates a new QueryConnectionConsensusStateRequest instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryConnectionConsensusStateRequest instance
           */
          public static create(
            properties?: ibc.core.connection.v1.IQueryConnectionConsensusStateRequest,
          ): ibc.core.connection.v1.QueryConnectionConsensusStateRequest;

          /**
           * Encodes the specified QueryConnectionConsensusStateRequest message. Does not implicitly {@link ibc.core.connection.v1.QueryConnectionConsensusStateRequest.verify|verify} messages.
           * @param m QueryConnectionConsensusStateRequest message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.connection.v1.IQueryConnectionConsensusStateRequest,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryConnectionConsensusStateRequest message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryConnectionConsensusStateRequest
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.connection.v1.QueryConnectionConsensusStateRequest;
        }

        /** Properties of a QueryConnectionConsensusStateResponse. */
        interface IQueryConnectionConsensusStateResponse {
          /** QueryConnectionConsensusStateResponse consensusState */
          consensusState?: google.protobuf.IAny | null;

          /** QueryConnectionConsensusStateResponse clientId */
          clientId?: string | null;

          /** QueryConnectionConsensusStateResponse proof */
          proof?: Uint8Array | null;

          /** QueryConnectionConsensusStateResponse proofPath */
          proofPath?: string | null;

          /** QueryConnectionConsensusStateResponse proofHeight */
          proofHeight?: ibc.core.client.v1.IHeight | null;
        }

        /** Represents a QueryConnectionConsensusStateResponse. */
        class QueryConnectionConsensusStateResponse implements IQueryConnectionConsensusStateResponse {
          /**
           * Constructs a new QueryConnectionConsensusStateResponse.
           * @param [p] Properties to set
           */
          constructor(p?: ibc.core.connection.v1.IQueryConnectionConsensusStateResponse);

          /** QueryConnectionConsensusStateResponse consensusState. */
          public consensusState?: google.protobuf.IAny | null;

          /** QueryConnectionConsensusStateResponse clientId. */
          public clientId: string;

          /** QueryConnectionConsensusStateResponse proof. */
          public proof: Uint8Array;

          /** QueryConnectionConsensusStateResponse proofPath. */
          public proofPath: string;

          /** QueryConnectionConsensusStateResponse proofHeight. */
          public proofHeight?: ibc.core.client.v1.IHeight | null;

          /**
           * Creates a new QueryConnectionConsensusStateResponse instance using the specified properties.
           * @param [properties] Properties to set
           * @returns QueryConnectionConsensusStateResponse instance
           */
          public static create(
            properties?: ibc.core.connection.v1.IQueryConnectionConsensusStateResponse,
          ): ibc.core.connection.v1.QueryConnectionConsensusStateResponse;

          /**
           * Encodes the specified QueryConnectionConsensusStateResponse message. Does not implicitly {@link ibc.core.connection.v1.QueryConnectionConsensusStateResponse.verify|verify} messages.
           * @param m QueryConnectionConsensusStateResponse message or plain object to encode
           * @param [w] Writer to encode to
           * @returns Writer
           */
          public static encode(
            m: ibc.core.connection.v1.IQueryConnectionConsensusStateResponse,
            w?: $protobuf.Writer,
          ): $protobuf.Writer;

          /**
           * Decodes a QueryConnectionConsensusStateResponse message from the specified reader or buffer.
           * @param r Reader or buffer to decode from
           * @param [l] Message length if known beforehand
           * @returns QueryConnectionConsensusStateResponse
           * @throws {Error} If the payload is not a reader or valid buffer
           * @throws {$protobuf.util.ProtocolError} If required fields are missing
           */
          public static decode(
            r: $protobuf.Reader | Uint8Array,
            l?: number,
          ): ibc.core.connection.v1.QueryConnectionConsensusStateResponse;
        }
      }
    }
  }
}

/** Namespace tendermint. */
export namespace tendermint {
  /** Namespace crypto. */
  namespace crypto {
    /** Properties of a Proof. */
    interface IProof {
      /** Proof total */
      total?: Long | null;

      /** Proof index */
      index?: Long | null;

      /** Proof leafHash */
      leafHash?: Uint8Array | null;

      /** Proof aunts */
      aunts?: Uint8Array[] | null;
    }

    /** Represents a Proof. */
    class Proof implements IProof {
      /**
       * Constructs a new Proof.
       * @param [p] Properties to set
       */
      constructor(p?: tendermint.crypto.IProof);

      /** Proof total. */
      public total: Long;

      /** Proof index. */
      public index: Long;

      /** Proof leafHash. */
      public leafHash: Uint8Array;

      /** Proof aunts. */
      public aunts: Uint8Array[];

      /**
       * Creates a new Proof instance using the specified properties.
       * @param [properties] Properties to set
       * @returns Proof instance
       */
      public static create(properties?: tendermint.crypto.IProof): tendermint.crypto.Proof;

      /**
       * Encodes the specified Proof message. Does not implicitly {@link tendermint.crypto.Proof.verify|verify} messages.
       * @param m Proof message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: tendermint.crypto.IProof, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes a Proof message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns Proof
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): tendermint.crypto.Proof;
    }

    /** Properties of a ValueOp. */
    interface IValueOp {
      /** ValueOp key */
      key?: Uint8Array | null;

      /** ValueOp proof */
      proof?: tendermint.crypto.IProof | null;
    }

    /** Represents a ValueOp. */
    class ValueOp implements IValueOp {
      /**
       * Constructs a new ValueOp.
       * @param [p] Properties to set
       */
      constructor(p?: tendermint.crypto.IValueOp);

      /** ValueOp key. */
      public key: Uint8Array;

      /** ValueOp proof. */
      public proof?: tendermint.crypto.IProof | null;

      /**
       * Creates a new ValueOp instance using the specified properties.
       * @param [properties] Properties to set
       * @returns ValueOp instance
       */
      public static create(properties?: tendermint.crypto.IValueOp): tendermint.crypto.ValueOp;

      /**
       * Encodes the specified ValueOp message. Does not implicitly {@link tendermint.crypto.ValueOp.verify|verify} messages.
       * @param m ValueOp message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: tendermint.crypto.IValueOp, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes a ValueOp message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns ValueOp
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): tendermint.crypto.ValueOp;
    }

    /** Properties of a DominoOp. */
    interface IDominoOp {
      /** DominoOp key */
      key?: string | null;

      /** DominoOp input */
      input?: string | null;

      /** DominoOp output */
      output?: string | null;
    }

    /** Represents a DominoOp. */
    class DominoOp implements IDominoOp {
      /**
       * Constructs a new DominoOp.
       * @param [p] Properties to set
       */
      constructor(p?: tendermint.crypto.IDominoOp);

      /** DominoOp key. */
      public key: string;

      /** DominoOp input. */
      public input: string;

      /** DominoOp output. */
      public output: string;

      /**
       * Creates a new DominoOp instance using the specified properties.
       * @param [properties] Properties to set
       * @returns DominoOp instance
       */
      public static create(properties?: tendermint.crypto.IDominoOp): tendermint.crypto.DominoOp;

      /**
       * Encodes the specified DominoOp message. Does not implicitly {@link tendermint.crypto.DominoOp.verify|verify} messages.
       * @param m DominoOp message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: tendermint.crypto.IDominoOp, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes a DominoOp message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns DominoOp
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): tendermint.crypto.DominoOp;
    }

    /** Properties of a ProofOp. */
    interface IProofOp {
      /** ProofOp type */
      type?: string | null;

      /** ProofOp key */
      key?: Uint8Array | null;

      /** ProofOp data */
      data?: Uint8Array | null;
    }

    /** Represents a ProofOp. */
    class ProofOp implements IProofOp {
      /**
       * Constructs a new ProofOp.
       * @param [p] Properties to set
       */
      constructor(p?: tendermint.crypto.IProofOp);

      /** ProofOp type. */
      public type: string;

      /** ProofOp key. */
      public key: Uint8Array;

      /** ProofOp data. */
      public data: Uint8Array;

      /**
       * Creates a new ProofOp instance using the specified properties.
       * @param [properties] Properties to set
       * @returns ProofOp instance
       */
      public static create(properties?: tendermint.crypto.IProofOp): tendermint.crypto.ProofOp;

      /**
       * Encodes the specified ProofOp message. Does not implicitly {@link tendermint.crypto.ProofOp.verify|verify} messages.
       * @param m ProofOp message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: tendermint.crypto.IProofOp, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes a ProofOp message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns ProofOp
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): tendermint.crypto.ProofOp;
    }

    /** Properties of a ProofOps. */
    interface IProofOps {
      /** ProofOps ops */
      ops?: tendermint.crypto.IProofOp[] | null;
    }

    /** Represents a ProofOps. */
    class ProofOps implements IProofOps {
      /**
       * Constructs a new ProofOps.
       * @param [p] Properties to set
       */
      constructor(p?: tendermint.crypto.IProofOps);

      /** ProofOps ops. */
      public ops: tendermint.crypto.IProofOp[];

      /**
       * Creates a new ProofOps instance using the specified properties.
       * @param [properties] Properties to set
       * @returns ProofOps instance
       */
      public static create(properties?: tendermint.crypto.IProofOps): tendermint.crypto.ProofOps;

      /**
       * Encodes the specified ProofOps message. Does not implicitly {@link tendermint.crypto.ProofOps.verify|verify} messages.
       * @param m ProofOps message or plain object to encode
       * @param [w] Writer to encode to
       * @returns Writer
       */
      public static encode(m: tendermint.crypto.IProofOps, w?: $protobuf.Writer): $protobuf.Writer;

      /**
       * Decodes a ProofOps message from the specified reader or buffer.
       * @param r Reader or buffer to decode from
       * @param [l] Message length if known beforehand
       * @returns ProofOps
       * @throws {Error} If the payload is not a reader or valid buffer
       * @throws {$protobuf.util.ProtocolError} If required fields are missing
       */
      public static decode(r: $protobuf.Reader | Uint8Array, l?: number): tendermint.crypto.ProofOps;
    }
  }
}
