"""Effect / sink taxonomy — a PORT of ``codegraph/src/ui-server/api/effects.ts``.

Purpose
The TypeScript module curates the calls that leave the index and change
something outside the process, for CodeGraph's Steps view. This is a faithful
port of its 12-category table — ``network, storage, device, telemetry,
database, response, queue, email, payments, cache, auth, process`` — matched on
the CALL AS WRITTEN (the whole member chain: ``prisma.article.findFirst``,
``this.jwtService.signAsync``, ``res.status(404).json``), because the index
keeps only the last segment of a deep chain.

Laws
Order matters: the first matching rule wins, so the specific rows sit above the
general ones (a Swift keychain is storage before the generic ``x.delete``
database row takes it; ``res.status.json`` is a response before ``fetch`` is
network). Language gates keep a rule from firing where it means something else:
a bare ``open(…)`` is a file in Python and nothing in TypeScript; ``session.get``
is the ORM in Python and a request in the browser. A rule without a gate
applies everywhere.

Invariants
What this module adds for SAST: the same curated sink lists, callable from
Python with no Node runtime, so a hunter can ask "what does this call leave the
process for?" and get ``['database', 'network']`` back as a list of strings.
Nothing here is a finding — a category is not a vulnerability, it is where a
vulnerability would have to live.

Format laws
The rules match normalized call spellings and return one of the 12
category strings; database results may also carry model/access fields.

Faithfulness notes (deliberate, not drift):
 - The TS ``(?<![Vv]iew)`` lookbehind and ``(?!…)`` negative lookahead port
   directly: both are fixed-width in CPython's ``re``.
 - One TS rule ends in a stray unmatched ``)`` (the Spring ``ResponseEntity``
   row); it is kept verbatim so the two tables stay line-for-line comparable.
 - ``only`` gates are family names (``js``, ``py`` …), not CodeGraph language
   values; :data:`FAMILIES` maps between them exactly as the TS does.
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# families
# ---------------------------------------------------------------------------

# CodeGraph ``nodes.language`` value -> the family name a rule gate uses.
# Exactly the TS FAMILIES table.
FAMILIES: dict[str, frozenset[str]] = {
    "js": frozenset({"javascript", "typescript", "tsx", "jsx"}),
    "py": frozenset({"python"}),
    "jvm": frozenset({"java", "kotlin", "scala"}),
    "cs": frozenset({"csharp"}),
    "go": frozenset({"go"}),
    "c": frozenset({"c", "cpp", "objc"}),
    "rb": frozenset({"ruby"}),
    "php": frozenset({"php"}),
    "swift": frozenset({"swift"}),
    "rs": frozenset({"rust"}),
}

# ---------------------------------------------------------------------------
# shared sub-patterns
# ---------------------------------------------------------------------------

# Built-in receivers a `Type.op` rule must never take for a model.
# Written with the same ^…$ anchors the TS regex carries so the negative
# lookahead below can slice them off exactly as BUILTIN_RECEIVERS.source.slice(1,-1).
_BUILTIN_RECEIVERS_SRC = r"^(?:Object|Array|Promise|Date|Map|Set|WeakMap|WeakSet|Reflect|Buffer|JSON|Math|Number|String|Symbol|Error|BigInt|Intl|Atomics|Proxy|Function|Boolean|RegExp|globalThis|window|document|console|process|List|Dict|Optional|Collections|Arrays|Objects|Stream|Task|Enumerable|Convert|Guid|DateTime|TimeSpan|Path|Regex)$"
_BUILTIN_RECEIVERS_INNER = _BUILTIN_RECEIVERS_SRC[1:-1]

ORM_STATIC_OPS = (
    r"(?:find|findOne|findAll|findById|findByPk|findMany|findFirst|findUnique|findOrCreate|findAndCountAll|create|createMany|update|updateOne|updateMany|upsert|delete|deleteOne|deleteMany|destroy|save|insert|insertMany|aggregate|count|countDocuments|bulkCreate|bulkWrite|exists|distinct|where|query|all|first|last|pluck|find_by|find_each|find_or_create_by|create!|update!|destroy_all|delete_all|update_all|insert_all|upsert|includes|joins|order|limit|scope|select)"
)

# A method that reads or writes a store — what makes `userModel.find` the
# database and `viewModel.load` nothing.
DB_OP = (
    r"(?:find\w*|get|getOne|getMany|getAll|getById|count\w*|aggregate|create\w*|update\w*|upsert|delete\w*|remove\w*|save\w*|insert\w*|exists|query\w*|execute\w*|exec|raw|persist|merge|flush|first\w*|last\w*|all|any\w*|toList\w*|toArray\w*|select\w*|where|orderBy|distinct|paginate|truncate|drop|Add\w*|Remove\w*|Update\w*|Find\w*|First\w*|Single\w*|ToList\w*|Count\w*|Any\w*|Create|Save|Delete|Where|Get|Select|Query\w*|Exec\w*|InsertOne|InsertMany|FindOne|UpdateOne|DeleteOne|DeleteMany|ReplaceOne|CountDocuments|bulk\w*|batch\w*)"
)


def _compile(pattern: str, flags: int = 0) -> re.Pattern:
    """Compile a rule pattern once; the table stores compiled objects."""
    return re.compile(pattern, flags)


def _rule(category: str, pattern: str, only=None, instantiates: bool = False) -> dict:
    """One effect rule: category, compiled pattern, family gate, instantiation."""
    return {
        "category": category,
        "pattern": _compile(pattern),
        "only": frozenset(only) if only else None,
        "instantiates": instantiates,
    }


# ---------------------------------------------------------------------------
# the table. Order matters: first match wins.
# ---------------------------------------------------------------------------

EFFECT_RULES: list[dict] = [
    # ---------------------------------------------------------------- response --
    _rule("response", r"^(?:res|response|reply|rep|ctx|c|context)(?:\.(?:status|sendStatus|code|type|header|headers|set|append|cookie|clearCookie|vary|location|links|format))*\.(?:status|json|jsonp|send|sendStatus|end|redirect|render|sendFile|download|attachment|write|writeHead|code|type|header|set|cookie|body|text|html|notFound|stream|file|view|throw|assert)$", ["js"]),
    _rule("response", r"^(?:NextResponse|Response)\.(?:json|redirect|rewrite|next|error)$|^(?:createError|createHttpError|httpErrors\.\w+|Boom\.\w+|boom\.\w+|HttpError|HTTPError)$", ["js"]),
    _rule("response", r"^(?:NextResponse|Response)$", ["js"], True),
    _rule("response",
          r"^(?:HTTPException|JSONResponse|Response|RedirectResponse|StreamingResponse|FileResponse|HTMLResponse|PlainTextResponse|ORJSONResponse|jsonify|abort|make_response|redirect|render_template|send_file|send_from_directory|JsonResponse|HttpResponse|HttpResponseRedirect|HttpResponsePermanentRedirect|HttpResponseNotFound|HttpResponseBadRequest|HttpResponseForbidden|HttpResponseNotAllowed|HttpResponseServerError|Http404|render|get_object_or_404|get_list_or_404|NotFound|PermissionDenied|ValidationError|AuthenticationFailed|NotAuthenticated|ParseError|MethodNotAllowed|Throttled|APIException|status\.HTTP_\w+)$", ["py"]),
    _rule("response", r"^ResponseEntity(?:\.\w+)*$|^ResponseStatusException$|^(?:ServerResponse|Mono\.just\(ResponseEntity)", ["jvm"]),
    # Spring MVC's other two answers: a view to render, and a redirect.
    _rule("response", r"^(?:ModelAndView|RedirectView)$", ["jvm"], True),
    _rule("response",
          r"^(?:Ok|NotFound|BadRequest|Created|CreatedAtAction|CreatedAtRoute|NoContent|Unauthorized|Forbid|Accepted|AcceptedAtAction|Problem|StatusCode|Conflict|UnprocessableEntity|Redirect|RedirectPermanent|RedirectToAction|RedirectToPage|RedirectToRoute|LocalRedirect|View|PartialView|Json|File|PhysicalFile|Content|Challenge|SignIn|SignOut|ValidationProblem|Page)$|^(?:Results|TypedResults)\.\w+$|^(?:Response|HttpContext\.Response)\.(?:WriteAsync|WriteAsJsonAsync|Redirect|StatusCode)$", ["cs"]),
    _rule("response",
          r"^(?:c|ctx|g)\.(?:JSON|IndentedJSON|PureJSON|AsciiJSON|SecureJSON|JSONP|XML|YAML|TOML|ProtoBuf|String|HTML|Data|DataFromReader|File|FileAttachment|Redirect|Render|Status|AbortWithStatus|AbortWithStatusJSON|AbortWithError|Abort|Error|SendString|SendStatus|Send|Blob|Stream|NoContent|Attachment|Format)$|^http\.(?:Error|Redirect|NotFound|ServeFile|ServeContent)$|^(?:w|rw|res|writer)\.(?:WriteHeader|Write|Header)$|^(?:render|json|xml)\.\w+$", ["go"]),
    _rule("response", r"^(?:Abort|Response|HTTPStatus\.\w+|req\.redirect|request\.redirect)$", ["swift"]),
    _rule("response", r"^(?:render|redirect_to|redirect_back|head|respond_to|respond_with|send_data|send_file|render_to_string)$", ["rb"]),
    # Chains reach the rules without their argument lists: `response()->json(…)`
    # is `response->json`, `redirect()->back()->withErrors(…)` is
    # `redirect->back->withErrors`.
    _rule("response", r"^(?:response|abort|abort_if|abort_unless|redirect|view|back|json|to_route)(?:->\w+)*$", ["php"]),
    _rule("response", r"^(?:HttpResponse|Json|StatusCode|Redirect|NamedFile|HttpResponseBuilder)(?:::\w+)*$", ["rs"]),

    # ---------------------------------------------------------------- database --
    # A keychain is storage, whatever its method is named: Swift's generic
    # `x.delete` database row below would take `keychain.delete(key)`.
    # The receiver is the keychain (`keychain`, `appKeychain`, `KeychainSwift`),
    # not `keychainAccounts`.
    _rule("storage", r"^(?:self\.)?(?:\w*[kK]eychain|Keychain\w*)(?:\.\w+)+$", ["swift"]),
    _rule("database", r"^(?:this\.)?(?:prisma|db|database|orm|em|entityManager|dataSource|queryRunner|knex|kysely|sequelize|mongoose|drizzle|sql|pool|pg|pgClient|conn|connection|repo|repository|collection|trx|tx|typeorm|dbClient|mongo|mongoClient)\.(?:\w+\.)?\$?\w+$", ["js"]),
    _rule("database", r"^(?:this\.)?_?\w*(?:Repository|Repo|Dao|DAO|Mapper|EntityManager|DataSource|Knex|Prisma|Kysely|Drizzle|Sequelize|DbContext|DbSet)\.(?:\w+\.)?\w+$", ["js", "jvm", "cs", "go", "rs", "swift", "rb"]),
    # `viewModel.votes.firstIndex(of:)`: a view model is UI state, not a table.
    _rule("database", r"^(?:this\.)?_?\w*(?<![Vv]iew)(?:Model|Entity|Collection|Table|Db|DB|Database|Datastore)\.(?:\w+\.)?" + DB_OP + r"$", ["js", "jvm", "cs", "go", "rs", "swift", "rb"]),
    _rule("database", r"^(?!" + _BUILTIN_RECEIVERS_INNER + r"\b)[A-Z]\w*\." + ORM_STATIC_OPS + r"$", ["js", "rb", "swift", "php"]),
    _rule("database", r"^(?:self\.)?(?:\w*_)?(?:session|db|database|engine|cursor|conn|connection|Session)\.(?:session\.)?(?:query|add|add_all|commit|execute|executemany|exec|delete|refresh|flush|rollback|get|merge|scalars?|scalar_one\w*|one|one_or_none|first|all|begin|close|expunge|bulk_\w+|select|insert|update|fetchone|fetchall|fetchmany|create_all|drop_all|run_sync)$", ["py"]),
    _rule("database",
          r"^[A-Z]\w*\.(?:objects|query|_default_manager)(?:\.\w+)*$|^\w+\.objects\.\w+$|^(?:select|insert|update|delete|text|func\.\w+|bulk_create|bulk_update|get_object_or_404)$|^\w+\.(?:save|delete|refresh_from_db|get_or_create|update_or_create|filter|exclude|annotate|aggregate|values|values_list|select_related|prefetch_related|bulk_create|bulk_update|create|update|count|exists)$", ["py"]),
    _rule("database", r"^(?:this\.)?(?:\w*[rR]epository|\w*[rR]epo|\w*Dao|\w*DAO|\w*Mapper|jdbcTemplate|namedParameterJdbcTemplate|jdbc|entityManager|em|session|sessionFactory|mongoTemplate|mongoOperations|r2dbcEntityTemplate|databaseClient|criteriaBuilder|query|typedQuery|nativeQuery|jpaRepository|crudRepository|dsl|dslContext|create|template)\.(?:\w+\.)*\w+$", ["jvm"]),
    _rule("database", r"^(?:this\.)?_?(?:\w*[rR]epository|\w*[rR]epo|\w*Dao|\w*[cC]ontext|dbContext|db|_db|_context|connection|_connection|conn|_conn|collection|_collection|session|_session|unitOfWork|_unitOfWork|uow|_uow|dbSet|_dbSet)\.(?:\w+\.)*\w+$", ["cs"]),
    _rule("database",
          r"\.(?:SaveChanges|SaveChangesAsync|ToListAsync|ToArrayAsync|FirstOrDefaultAsync|SingleOrDefaultAsync|FirstAsync|SingleAsync|AnyAsync|CountAsync|ExecuteUpdateAsync|ExecuteDeleteAsync|ExecuteSqlRawAsync|ExecuteSqlAsync|FromSqlRaw|FromSql|AddAsync|AddRangeAsync|FindAsync|QueryAsync|QueryFirstOrDefaultAsync|QuerySingleAsync|ExecuteAsync|ExecuteScalarAsync|InsertOneAsync|InsertManyAsync|ReplaceOneAsync|UpdateOneAsync|DeleteOneAsync|DeleteManyAsync)$", ["cs"]),
    _rule("database",
          r"^(?:db|DB|tx|conn|pool|dbConn|client|repo|store|coll|collection|session|s\.db|r\.db|h\.db|s\.DB|h\.DB|a\.db|app\.db|q|queries|s\.queries|gorm|sqlx|dbx)\.(?:\w+\.)*(?:Query\w*|Exec\w*|Prepare\w*|Begin\w*|Create|First|Find|Save|Delete|Where|Updates?|Model|Table|Raw|Scan|Get|Select|NamedExec|InsertOne|InsertMany|FindOne|UpdateOne|UpdateMany|DeleteOne|DeleteMany|ReplaceOne|CountDocuments|Count|Take|Last|Preload|Joins|Order|Limit|Offset|Transaction|AutoMigrate|Migrate|Insert|Update|Upsert|Aggregate|Distinct|Pluck|Rows|Row|Set|Get\w+|List\w+|Create\w+|Update\w+|Delete\w+)$", ["go"]),
    _rule("database", r"^[A-Z]\w*\.(?:query|find|create|all|first|last|save|delete|update)$|^\w+\.(?:save|create|delete|update|query)$|^(?:req|request)\.db\.\w+$", ["swift"]),
    _rule("database", r"^(?:@?\w+)\.(?:save|save!|update|update!|update_attributes|destroy|destroy!|reload|touch|increment!|decrement!)$|^ActiveRecord::Base\.\w+$|^\w+\.(?:where|find|find_by|find_each|first|last|all|create|create!|pluck|count|exists\?|order|includes|joins|delete_all|update_all|insert_all|upsert_all|find_or_create_by)$", ["rb"]),
    _rule("database", r"^[A-Z]\w*::(?:find|findOrFail|findMany|create|firstOrCreate|updateOrCreate|where|whereIn|all|first|firstOrFail|query|insert|update|destroy|truncate|count|with|select|orderBy|paginate)$|^DB::\w+$|^\$\w+->(?:save|delete|update|create|fill|refresh|forceDelete|restore|increment|decrement|touch)$", ["php"]),
    _rule("database", r"^(?:sqlx|diesel|sea_orm|mongodb)(?:::\w+)*$|^\w+(?:::\w+)*::(?:find|find_by_id|insert|update|delete|save|find_many|find_one|filter)$|^(?:conn|pool|tx|db|client)\.(?:execute|query\w*|prepare|begin|commit|rollback|fetch\w*)$", ["rs"]),
    _rule("database", r"^(?:sqlite3_\w+|mysql_\w+|PQ\w+|SQLExec\w*|SQLPrepare|SQLFetch\w*|redis\w*Command|mongoc_\w+)$", ["c"]),

    # ------------------------------------------------------------------- queue --
    _rule("queue",
          r"^(?:this\.)?(?:\w*[qQ]ueue\w*)\.(?:add|addBulk|process|createJob|send|sendMessage|publish|push|enqueue)$|^(?:this\.)?(?:sqs|sqsClient|sns|snsClient|pubsub|topic|producer|kafka|kafkaProducer|rabbit|channel|amqp|nats|nc|eventBridge|bus|messageBus|eventBus|agenda|boss|pgBoss|inngest|trigger|client\.queue)\.(?:\w+\.)*(?:send|sendMessage|sendMessageBatch|publish|publishMessage|produce|emit|add|schedule|now|enqueue|sendToQueue|put|dispatch|trigger|createJob|createSchedule|invoke|batch)$|^(?:agenda|boss|pgBoss|inngest)\.\w+$", ["js"]),
    _rule("queue", r"^(?:SendMessageCommand|PublishCommand|PutEventsCommand|SendMessageBatchCommand|InvokeCommand)$", ["js"], True),
    _rule("queue", r"^\w+\.(?:delay|apply_async|send_task|si|s|enqueue|enqueue_call|enqueue_in|enqueue_at|send_message|send_message_batch|basic_publish|publish|produce|put_events|invoke)$|^(?:celery|app|current_app)\.send_task$|^(?:sqs|sns|producer|channel|queue|q|redis_queue|dramatiq|huey)\.\w+$", ["py"]),
    _rule("queue", r"^(?:this\.)?(?:\w*[tT]emplate|\w*[pP]ublisher|\w*[pP]roducer|\w*[qQ]ueue\w*|sqsClient|snsClient|amazonSQS|amazonSNS|eventBus|messageBus|bus|channel|rabbitTemplate|kafkaTemplate|jmsTemplate|streamBridge|eventPublisher|applicationEventPublisher)\.(?:send\w*|convertAndSend|publish\w*|publishEvent|produce|sendMessage|put\w*|emit|dispatch|enqueue)$", ["jvm"]),
    _rule("queue",
          r"^(?:this\.)?_?(?:bus|publishEndpoint|sendEndpoint|producer|queue\w*|channel|messageSession|serviceBus|serviceBusSender|topicClient|queueClient|eventGrid|BackgroundJob|RecurringJob|BackgroundJobClient|jobClient|_jobs|jobs)\.(?:\w+\.)*(?:Publish\w*|Send\w*|Produce\w*|Enqueue\w*|Schedule\w*|AddOrUpdate|BasicPublish|SendMessageAsync|SendMessagesAsync|Create\w*Message|Dispatch\w*|Trigger\w*)$", ["cs"]),
    _rule("queue", r"^(?:\w+\.)*(?:Publish|PublishMsg|PublishAsync|SendMessage|SendMessageWithContext|Produce|ProduceSync|Enqueue|EnqueueContext|PutEvents|WriteMessages|Emit|Dispatch|Schedule|SendMsg)$", ["go"]),
    _rule("queue", r"^\w+\.(?:perform_later|perform_async|perform_in|perform_at|deliver_later|set|publish|enqueue)$|^Sidekiq::Client\.\w+$", ["rb"]),
    _rule("queue", r"^(?:dispatch|dispatch_now|dispatch_sync|Queue::\w+|Bus::\w+|Event::dispatch|event|broadcast)$|^\w+::dispatch(?:Sync|Now|AfterResponse)?$|^\$\w+->dispatch$", ["php"]),

    # ------------------------------------------------------------------- email --
    _rule("email", r"^(?:this\.)?(?:\w*[mM]ail\w*|\w*[tT]ransporter|sgMail|sendgrid|resend|mailgun|postmark|ses|sesClient|sesv2|smtp|nodemailer|courier|brevo|sendinblue|mailjet|mandrill|loops|plunk)\.(?:\w+\.)*(?:send\w*|sendMail|sendEmail|sendTemplate|create|deliver|emails\.send|transactional\w*)$|^(?:SendEmailCommand|SendTemplatedEmailCommand|SendRawEmailCommand)$", ["js"]),
    _rule("email", r"^(?:send_mail|send_mass_mail|mail_admins|mail_managers|EmailMessage|EmailMultiAlternatives|mail\.send|mail\.send_message|smtplib\.SMTP|smtplib\.SMTP_SSL|ses\.send_email|ses\.send_raw_email|sg\.send|sendgrid\.\w+|resend\.Emails\.send|postmark\.\w+)$|^\w+\.send_(?:email|mail|message)$|^(?:smtp|server|mailer|email_client)\.(?:sendmail|send_message|send|login|starttls)$", ["py"]),
    _rule("email", r"^(?:this\.)?(?:\w*[mM]ailSender|\w*[mM]ailer|mailService|emailService|sesClient|amazonSimpleEmailService|transport|Transport)\.(?:send\w*|deliver)$|^Transport\.send$", ["jvm"]),
    _rule("email", r"^(?:this\.)?_?(?:emailSender|emailService|mailService|mailer|smtpClient|sendGridClient|sesClient|fluentEmail|email)\.(?:Send\w*)$|^Email\.(?:From|Send\w*)$", ["cs"]),
    _rule("email", r"^(?:smtp\.SendMail|mail\.Send\w*|\w+\.SendEmail\w*|\w+\.SendMail|ses\.SendEmail|sg\.Send|mg\.Send)$", ["go"]),
    _rule("email", r"^\w+Mailer\.\w+$|^\w+\.(?:deliver_now|deliver_later|deliver)$|^Mail\.deliver$", ["rb"]),
    _rule("email", r"^Mail::(?:to|send|raw|queue|bcc|cc)$|^Notification::send$|^\$\w+->notify$", ["php"]),

    # ---------------------------------------------------------------- payments --
    _rule("payments", r"^(?:this\.)?(?:stripe|Stripe|braintree|paypal|PayPal|square|razorpay|paddle|Paddle|adyen|mollie|chargebee|recurly|lemonSqueezy|lemonsqueezy|checkout|gateway|paymentGateway|paymentsClient|paymentService|_paymentService|stripeClient|stripeService|_stripe)\b"),

    # ------------------------------------------------------------------- cache --
    _rule("cache",
          r"^(?:this\.)?(?:redis|redisClient|ioredis|cache|cacheManager|cacheService|memcached|memcache|kv|KV|upstash|_cache|_distributedCache|_memoryCache|distributedCache|memoryCache|redisTemplate|stringRedisTemplate|jedis|lettuce|redisson|rdb|rc|cacheClient|caches|Cache|env\.\w*KV\w*)\.(?:\w+\.)*(?:get\w*|set\w*|del\w*|delete\w*|remove\w*|incr\w*|decr\w*|expire\w*|exists|has|hget\w*|hset\w*|hdel|hgetall|lpush|rpush|lpop|rpop|sadd|srem|smembers|zadd|zrange\w*|zrem|wrap|mget|mset|setex|setnx|ttl|keys|flush\w*|reset|clear|store|put\w*|evict|invalidate\w*|GetOrCreate\w*|GetString\w*|SetString\w*|GetOrSet\w*|Refresh\w*|Get|Set|Del|Delete|Exists|Expire|Incr|Decr|HGet\w*|HSet\w*|Publish|Subscribe|TryGetValue|CreateEntry|opsForValue|opsForHash|opsForList|opsForSet|Fetch|fetch|read|write|delete_pattern|delete_many|get_many|set_many|touch|add|remember|rememberForever|forget|pull|increment|decrement|forever|tags|memoize)$"),

    # -------------------------------------------------------------------- auth --
    _rule("auth",
          r"^(?:this\.)?(?:jwt|jsonwebtoken|jose|SignJWT|jwtVerify|bcrypt|bcryptjs|argon2|scrypt|passport|jwtService|_jwtService|tokenService|authService\.sign\w*|auth\.api|auth\.\w+|betterAuth|clerk|clerkClient|supabase\.auth|firebase\.auth|admin\.auth|getAuth|getServerSession|getSession|auth|lucia|nextauth|NextAuth|verifyIdToken|verifyToken|signToken|createSession|invalidateSession|oauth2|OAuth2Client|okta|auth0|cognito|CognitoIdentityServiceProvider|Keychain|crypto\.timingSafeEqual|crypto\.pbkdf2\w*|crypto\.scrypt\w*|crypto\.createHmac)\b(?:\.(?:\w+\.)*\w+)?$", ["js"]),
    _rule("auth",
          r"^(?:jwt|pyjwt|jose|bcrypt|argon2|passlib|pwd_context|password_hasher|hashers|check_password|make_password|authenticate|login|logout|login_required|get_user|verify_password|get_password_hash|create_access_token|create_refresh_token|decode_token|OAuth2PasswordBearer|HTTPBearer|HTTPBasic|Depends\(get_current_user\)|secrets\.\w+|hmac\.\w+|hashlib\.\w+|itsdangerous|serializer\.dumps|serializer\.loads|token_urlsafe|oauth|authlib|social_core|allauth)(?:\.(?:\w+\.)*\w+)?$", ["py"]),
    _rule("auth",
          r"^(?:this\.)?(?:passwordEncoder|bCryptPasswordEncoder|encoder|jwtUtil\w*|jwtService|jwtProvider|tokenProvider|tokenService|jwtDecoder|jwtEncoder|Jwts|JWT|Jwt|authenticationManager|authManager|SecurityContextHolder|securityContext|userDetailsService|BCrypt|Keys|Algorithm|Argon2\w*|SCrypt\w*|Pbkdf2\w*|MessageDigest|Mac|SecureRandom|keycloak|oauth2\w*|OAuth2\w*|clientRegistrationRepository|authorizedClientService)\.(?:\w+\.)*\w+$", ["jvm"]),
    _rule("auth",
          r"^(?:this\.)?_?(?:userManager|signInManager|roleManager|tokenHandler|jwtHandler|JwtSecurityTokenHandler|tokenService|jwtService|authService|authenticationService|passwordHasher|PasswordHasher|HttpContext\.SignInAsync|HttpContext\.SignOutAsync|HttpContext\.AuthenticateAsync|HttpContext\.ChallengeAsync|context\.SignInAsync|context\.SignOutAsync|identityService|_identityService|currentUser|_currentUser|user\.Identity|User\.Identity|User\.Claims|User\.IsInRole|BCrypt|Argon2|Rfc2898DeriveBytes|RandomNumberGenerator|SHA256|HMACSHA256|KeyDerivation|Convert\.ToBase64String)\.(?:\w+\.)*\w+$|^(?:JwtSecurityToken|JwtSecurityTokenHandler|SymmetricSecurityKey|SigningCredentials|ClaimsIdentity|ClaimsPrincipal|AuthenticationProperties)$", ["cs"]),
    _rule("auth", r"^(?:jwt|jose|paseto|bcrypt|argon2|scrypt|pbkdf2|hmac|sha256|oauth2|oidc|auth|authz|casbin|token|session|sessions|securecookie|gothic|goth)\.(?:\w+\.)*\w+$|^\w+\.(?:SignedString|ParseWithClaims|GenerateFromPassword|CompareHashAndPassword|Verify|VerifyToken|GenerateToken|ValidateToken|Authenticate|Authorize|Login|Logout|CheckPassword|HashPassword)$", ["go"]),
    _rule("auth",
          r"^(?:BCrypt::Password\.\w+|JWT\.(?:encode|decode)|sign_in|sign_out|sign_in_and_redirect|authenticate_user!|authenticate_with_http_token|authenticate_or_request_with_http_basic|current_user|has_secure_password|Devise\.\w+|warden\.\w+|OmniAuth\.\w+|Doorkeeper\.\w+|SecureRandom\.\w+|Digest::\w+\.\w+)$|^\w+\.(?:authenticate|authenticate!|regenerate_token|generate_token|valid_password\?)$", ["rb"]),
    _rule("auth", r"^(?:Auth::\w+|Hash::\w+|Password::\w+|Crypt::\w+|Gate::\w+|Socialite::\w+|Passport::\w+|Sanctum::\w+|JWTAuth::\w+|password_hash|password_verify|\$request->user|\$user->createToken|\$user->tokens)(?:\(\)->\w+)*$", ["php"]),
    _rule("auth", r"^(?:jsonwebtoken|bcrypt|argon2|scrypt|pbkdf2|hmac|sha2|ring|rustls|oauth2|openidconnect|jwt_simple|biscuit|paseto)(?:::\w+)*$", ["rs"]),
    _rule("auth", r"^(?:crypt|getpwnam|getpwuid|setuid|setgid|seteuid|PAM_\w+|pam_\w+|SSL_CTX_\w+|EVP_\w+|HMAC|RAND_bytes|BN_\w+|X509_\w+|gnutls_\w+)$", ["c"]),

    # ----------------------------------------------------------------- storage --
    _rule("storage", r"^(?:AsyncStorage|SecureStore|MMKV|localStorage|sessionStorage|indexedDB|UserDefaults|Keychain|KeychainAccess|FileSystem|RNFS|FileManager|fs|fsp|fs\.promises|promises|path\.write|Deno\.(?:writeFile|readFile|writeTextFile|readTextFile|remove|mkdir|open|create|stat)|Bun\.(?:write|file))\b"),
    _rule("storage",
          r"^(?:this\.)?(?:s3|s3Client|S3|storage|bucket|gcs|blob|blobClient|blobService|containerClient|cloudinary|uploader|uploadthing|utapi|supabase\.storage|firebase\.storage|storageRef|ref|getStorage|minio|minioClient|r2|R2|env\.\w*(?:BUCKET|R2)\w*|sharp|multer)\.(?:\w+\.)*(?:putObject|getObject|deleteObject|listObjects\w*|upload\w*|download\w*|send|file|save|delete|remove|getSignedUrl|createSignedUrl|createReadStream|createWriteStream|put|get|head|copy|move|exists|list|write\w*|read\w*|toFile|toBuffer|from|upload_stream|destroy|createPresignedPost|presign\w*|bucket|object)$|^(?:PutObjectCommand|GetObjectCommand|DeleteObjectCommand|CopyObjectCommand|HeadObjectCommand|ListObjectsV2Command|CreateMultipartUploadCommand|UploadPartCommand|Upload)$", ["js"]),
    _rule("storage",
          r"^(?:open|os\.(?:remove|unlink|rename|replace|makedirs|mkdir|rmdir|removedirs|listdir|scandir|walk|chmod|chown|stat|path\.exists|path\.isfile|path\.isdir|path\.getsize|symlink|link|truncate|utime|fsync)|shutil\.\w+|tempfile\.\w+|Path\(\w*\)\.(?:write_text|write_bytes|read_text|read_bytes|unlink|mkdir|rmdir|rename|replace|touch|exists|iterdir|glob|rglob|open)|\w+\.(?:write_text|write_bytes|read_text|read_bytes|unlink|mkdir|rmdir|touch)|boto3\.(?:client|resource)|s3\.(?:upload_file|upload_fileobj|download_file|download_fileobj|put_object|get_object|delete_object|list_objects\w*|head_object|copy_object|generate_presigned_url|create_bucket)|s3_client\.\w+|bucket\.(?:upload_file|download_file|put_object|delete_objects|objects)|default_storage\.\w+|storage\.\w+|FileSystemStorage|blob\.(?:upload_from_\w+|download_as_\w+|download_to_\w+|delete|exists)|bucket\.blob|gcs\.\w+|blob_client\.\w+|container_client\.\w+|json\.dump|pickle\.dump|pickle\.load|json\.load|csv\.writer|csv\.reader|zipfile\.ZipFile|tarfile\.open|gzip\.open|aiofiles\.open|anyio\.open_file|shelve\.open|sqlite3\.connect|dbm\.open)$", ["py"]),
    _rule("storage",
          r"^(?:this\.)?(?:\w*[dD]ataStore|\w*[pP]references|\w*[pP]refs|sharedPreferences|prefs|editor)\.(?:updateData|edit|data|apply|commit|getString|putString|getInt|putInt|getLong|putLong|getBoolean|putBoolean|getFloat|putFloat|getStringSet|putStringSet|remove|clear|contains)$|^(?:this\.)?(?:context|applicationContext|appContext|ctx)\.(?:openFileOutput|openFileInput|getSharedPreferences|deleteFile|getFilesDir|getCacheDir|getExternalFilesDir|getDatabasePath|deleteDatabase|contentResolver\.\w+)$|^(?:this\.)?(?:contentResolver|resolver)\.(?:query|insert|update|delete|openInputStream|openOutputStream)$", ["jvm"]),
    _rule("queue", r"^(?:this\.)?(?:\w*[wW]orkManager|\w*[sS]cheduler|jobScheduler|alarmManager|\w*AlarmManager)\.(?:enqueue\w*|beginWith|beginUniqueWork|cancel\w*|schedule\w*|set\w*|setExact\w*|setRepeating|setInexactRepeating)$", ["jvm"]),
    _rule("storage",
          r"^(?:Files|Paths|File|FileUtils|IOUtils|FileSystems|Channels|FileChannel)\.\w+$|^(?:this\.)?(?:s3Client|amazonS3|s3|storage|gcsStorage|blobClient|blobServiceClient|containerClient|minioClient|storageService|fileService|fileStorage|resourceLoader|resource)\.(?:\w+\.)*\w+$|^(?:FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|BufferedWriter|BufferedReader|PrintWriter|PutObjectRequest|GetObjectRequest|DeleteObjectRequest|ObjectMetadata)$", ["jvm"]),
    _rule("storage",
          r"^(?:File|Directory|Path\.(?:Combine)?|FileInfo|DirectoryInfo|FileStream|StreamWriter|StreamReader|BinaryWriter|BinaryReader|ZipFile|ZipArchive|IsolatedStorageFile)(?:\.\w+)*$|^(?:this\.)?_?(?:s3Client|blobClient|blobServiceClient|containerClient|blobContainer|storage|storageService|fileStorage|fileService|fileProvider|_fileProvider|amazonS3|minio|minioClient)\.(?:\w+\.)*\w+$|^(?:FileStream|StreamWriter|StreamReader|BinaryWriter|BinaryReader|PutObjectRequest|GetObjectRequest|DeleteObjectRequest|TransferUtility)$", ["cs"]),
    _rule("storage",
          r"^(?:os|ioutil|io|filepath|bufio|afero|fs)\.(?:Open|OpenFile|Create|CreateTemp|ReadFile|WriteFile|Remove|RemoveAll|MkdirAll|Mkdir|MkdirTemp|Rename|Stat|Lstat|ReadDir|Chmod|Chown|Truncate|Symlink|Link|Readlink|Copy|CopyN|WriteString|Walk|WalkDir|Glob|NewWriter|NewReader|TempDir|TempFile|ReadAll)$|^(?:f|file|fd|w|writer)\.(?:Write\w*|Read\w*|Close|Sync|Seek|Truncate|WriteString)$|^(?:s3|s3Client|svc|uploader|downloader|storage|bucket|client|minioClient|blob)\.(?:PutObject\w*|GetObject\w*|DeleteObject\w*|ListObjects\w*|HeadObject\w*|CopyObject\w*|Upload\w*|Download\w*|Object|Bucket|Write|NewWriter|NewReader|FPutObject|FGetObject|PresignedGetObject|PresignedPutObject)$", ["go"]),
    _rule("storage",
          r"^(?:fopen|freopen|fclose|fread|fwrite|fgets|fputs|fgetc|fputc|fscanf|fprintf|fflush|fseek|ftell|rewind|open|openat|creat|close|read|write|pread|pwrite|lseek|unlink|unlinkat|remove|rename|renameat|mkdir|mkdirat|rmdir|stat|fstat|lstat|fstatat|access|chmod|fchmod|chown|fchown|truncate|ftruncate|fsync|fdatasync|opendir|fdopendir|readdir|closedir|rewinddir|mmap|munmap|msync|flock|fcntl|dup|dup2|pipe|mkstemp|mkdtemp|tmpfile|realpath|readlink|symlink|link|utime|utimes|futimes|sendfile|copy_file_range|ioctl|CreateFile\w*|ReadFile|WriteFile|CloseHandle|DeleteFile\w*|MoveFile\w*|CopyFile\w*|CreateDirectory\w*|RemoveDirectory\w*|FindFirstFile\w*|FindNextFile\w*|GetFileAttributes\w*|SetFilePointer\w*|FlushFileBuffers|std::ofstream|std::ifstream|std::fstream|ofstream|ifstream|fstream|std::filesystem::\w+|filesystem::\w+|fs::\w+)$", ["c"]),
    _rule("storage", r"^(?:File|Dir|FileUtils|IO|Pathname|Tempfile)\.\w+$|^(?:Aws::S3::\w+|S3_BUCKET\.\w+|ActiveStorage::\w+|\w+\.attach|\w+\.purge|\w+\.purge_later)$", ["rb"]),
    _rule("storage", r"^(?:Storage::\w+|File::\w+|file_put_contents|file_get_contents|fopen|fwrite|fread|fclose|unlink|mkdir|rmdir|rename|copy|move_uploaded_file|\$request->file|\$file->store\w*|\$file->move)(?:\(\)->\w+)*$", ["php"]),
    _rule("storage", r"^(?:std::fs|fs|tokio::fs|File|OpenOptions|std::io::Write|BufWriter|BufReader)(?:::\w+)*$|^\w+\.(?:write_all|read_to_string|read_to_end|sync_all|flush)$", ["rs"]),

    # ----------------------------------------------------------------- network --
    _rule("network",
          r"^(?:fetch|axios|ky|got|superagent|XMLHttpRequest|WebSocket|EventSource|undici|request|needle|phin|ofetch|\$fetch|useFetch|useAsyncData|wretch|redaxios)$|^(?:this\.)?(?:axios|api|client|http|https|httpClient|apiClient|instance|request|agent|graphql|apollo|apolloClient|urql|trpc|supabase|octokit|github|gh|openai|anthropic|ai|slack|twilio|sdk|\w+Client|\w+Api|\w+API|\w+Sdk|\w+SDK|\$http|\$axios|\$api|api\.\w+|routes\.\w+|server\.\w+)\.(?:\w+\.)*(?:get|post|put|patch|delete|head|options|request|query|mutate|mutation|rpc|invoke|call|send|fetch|create|list|retrieve|update|del|remove|upload|download|stream|connect|subscribe|emit|generate|complete|chat\.completions\.create|messages\.create|embeddings\.create|images\.generate|run|search|execute|useQuery|useMutation|useInfiniteQuery|prefetchQuery|fetchQuery|ensureQueryData)$|^URLSession(?:\.|$)|^(?:Alamofire|AF)\.|\.(?:dataTask|uploadTask|downloadTask)$|^(?:io|socket|ws|wss|pusher|ably|centrifuge|mqtt|mqttClient|nc|nats|grpc|grpcClient|stub)\.(?:emit|send|publish|connect|request|call|to|in|of|subscribe|unsubscribe|invoke)$|^(?:io|WebSocket|EventSource|XMLHttpRequest|Pusher|Ably|Centrifuge)$", ["js"]),
    _rule("network",
          r"^(?:requests|httpx|aiohttp|urllib\.request|urllib3|http\.client|httplib2|treq|niquests|pycurl|websockets|websocket|socketio|sio|grpc|stub|channel|zmq|paho|mqtt|client|http_client|api_client|api|session_client|async_client|_client|self\.client|self\.http|self\.session_client|slack_client|openai|anthropic|boto3\.client|lambda_client|sqs_client|sns_client|ses_client|ec2|s3)\.(?:\w+\.)*(?:get|post|put|patch|delete|head|options|request|send|fetch|urlopen|open|ClientSession|AsyncClient|Client|Session|stream|connect|emit|invoke|call|create|chat\.completions\.create|messages\.create|completions\.create|embeddings\.create|generate|retrieve|list|update|search|query)$|^(?:urlopen|Request|websockets\.connect|aiohttp\.ClientSession|httpx\.AsyncClient|httpx\.Client|requests\.Session|socket\.socket|socket\.create_connection|grpc\.insecure_channel|grpc\.secure_channel|grpc\.aio\.insecure_channel)$", ["py"]),
    _rule("network",
          r"^(?:this\.)?(?:restTemplate|webClient|httpClient|client|okHttpClient|retrofit|feignClient|\w*[cC]lient|\w*Feign|\w*Api|\w*Stub|\w*BlockingStub|\w*AsyncStub|graphQlClient|restClient|RestClient|WebClient|HttpClient|HttpRequest|Unirest|Jsoup|template)\.(?:\w+\.)*(?:getForObject|getForEntity|postForObject|postForEntity|postForLocation|exchange|execute|put|delete|patchForObject|get|post|patch|head|options|send|sendAsync|newCall|retrieve|bodyToMono|bodyToFlux|create|builder|newBuilder|newHttpClient|connect|call|invoke|newRequest|uri|method|request|body|block|subscribe|fetch|execute\w*|list\w*|get\w+|create\w+|update\w+|delete\w+)$|^(?:Socket|ServerSocket|URL|HttpURLConnection|HttpsURLConnection|DatagramSocket|WebSocketClient|StompSession|ManagedChannelBuilder)$", ["jvm"]),
    _rule("network",
          r"^(?:this\.)?_?(?:httpClient|client|http|httpClientFactory|\w*[cC]lient|\w*Api|graphQLClient|restClient|flurl|\w+\.WithOAuthBearerToken)\.(?:\w+\.)*(?:GetAsync|PostAsync|PutAsync|PatchAsync|DeleteAsync|SendAsync|GetStringAsync|GetStreamAsync|GetByteArrayAsync|GetFromJsonAsync|PostAsJsonAsync|PutAsJsonAsync|PatchAsJsonAsync|DeleteFromJsonAsync|Send|CreateClient|GetJsonAsync|PostJsonAsync|ReceiveJson|ReceiveString|InvokeAsync|SendCoreAsync|StartAsync|ConnectAsync|Get\w+Async|Post\w+Async|Put\w+Async|Delete\w+Async|List\w+Async|Create\w+Async|Update\w+Async|Invoke\w+Async|Execute\w*Async)$|^(?:HttpClient|HttpRequestMessage|WebClient|HttpWebRequest|TcpClient|UdpClient|Socket|ClientWebSocket|HubConnection|HubConnectionBuilder|GrpcChannel|RestClient|RestRequest|FlurlClient)$", ["cs"]),
    _rule("network",
          r"^(?:http|client|httpClient|c|hc|resty|req|grpc|net|websocket|ws|conn|nc|nats|mqtt|redis|rdb|\w+Client|\w+client|svc|api|sdk)\.(?:\w+\.)*(?:Get|Post|PostForm|Put|Patch|Delete|Head|Do|NewRequest|NewRequestWithContext|R|Dial|DialContext|DialTLS|Listen|ListenAndServe|Invoke|NewStream|Connect|Send|Recv|Request|Call|Write\w*|Read\w*|Publish|Subscribe|SendMessage|Ping|Execute|Fetch|Query|Mutate|Invoke\w*|Get\w+|Post\w+|Put\w+|Delete\w+|List\w+|Create\w+|Update\w+|Describe\w+)$|^(?:http|net|grpc|websocket|resty|fasthttp|gorequest|req)\.(?:Get|Post|PostForm|Head|Dial|DialContext|Listen|ListenAndServe|ListenAndServeTLS|NewClient|NewRequest|Serve|DefaultDialer\.Dial|Upgrade)$", ["go"]),
    _rule("network",
          r"^(?:socket|connect|bind|listen|accept|accept4|send|sendto|sendmsg|recv|recvfrom|recvmsg|getaddrinfo|gethostbyname|getnameinfo|inet_pton|inet_ntop|setsockopt|getsockopt|shutdown|select|poll|epoll_create\w*|epoll_ctl|epoll_wait|kqueue|kevent|curl_easy_init|curl_easy_setopt|curl_easy_perform|curl_easy_cleanup|curl_multi_\w+|SSL_new|SSL_connect|SSL_accept|SSL_read|SSL_write|SSL_shutdown|SSL_free|BIO_\w+|WSAStartup|WSASocket\w*|WSASend|WSARecv|WSACleanup|closesocket|ioctlsocket|http_\w+|uv_tcp_\w*|uv_udp_\w*|uv_connect|uv_listen|uv_read_start|uv_write|evhttp_\w*|bufferevent_\w*|nng_\w+|zmq_\w+|MHD_\w+|mg_\w+|lws_\w+|ares_\w+|anetTcpConnect|anetTcpServer|anetAccept|anetRead|anetWrite|connSocket\w*|connConnect|connWrite|connRead|connAccept|connListen|aeCreateFileEvent|aeDeleteFileEvent)$", ["c"]),
    _rule("network", r"^(?:Net::HTTP(?:\.\w+)*|HTTParty\.\w+|Faraday(?:\.\w+)*|RestClient\.\w+|HTTP\.\w+|Excon\.\w+|Typhoeus\.\w+|OpenURI\.open_uri|URI\.open|open-uri|Socket\.\w+|TCPSocket\.\w+|WebSocket::\w+|ActionCable\.server\.broadcast|\w+Channel\.broadcast_to|\w+Channel\.broadcast|\w+\.broadcast)$|^\w+\.(?:get|post|put|patch|delete|head|request)$", ["rb"]),
    _rule("network", r"^(?:Http::\w+|Http::\w+::\w+|curl_init|curl_exec|curl_setopt\w*|curl_close|file_get_contents|fsockopen|stream_socket_client|socket_create|socket_connect|socket_send|socket_recv|\$client->(?:request|get|post|put|patch|delete|send|sendAsync|requestAsync)|\$guzzle->\w+|\$http->\w+)(?:\(\)->\w+)*$", ["php"]),
    _rule("network", r"^(?:reqwest|hyper|ureq|isahc|surf|tonic|tungstenite|tokio_tungstenite|websocket|TcpStream|TcpListener|UdpSocket|Client|ClientBuilder|Request|awc)(?:::\w+)*$|^\w+\.(?:get|post|put|patch|delete|head|send|execute|connect|bind|send_to|recv_from|write_all|read_to_end)$", ["rs"]),
    _rule("network",
          r"^URLSession(?:\.|$)|^(?:Alamofire|AF)\.|\.(?:dataTask|uploadTask|downloadTask|webSocketTask|responseDecodable|responseJSON|responseData)$|(?:^|\.)\w*[sS]ession\.(?:data|upload|download|bytes)$|^(?:NWConnection|NWListener|NWBrowser|URLSessionWebSocketTask|WebSocket|Starscream|SocketManager|SocketIOClient|Socket)\b|^(?:this\.|self\.)?(?:client|api|apiClient|http|httpClient|networkService|network|session)\.(?:get|post|put|patch|delete|request|send|fetch|perform|execute|call|data|upload|download)$", ["swift"]),

    # ------------------------------------------------------------------ device --
    _rule("device",
          r"^(?:Linking|Share|Clipboard|Notifications|Camera|ImagePicker|MediaLibrary|Haptics|Alert|Vibration|Location|Geolocation|Permissions|UIApplication|AVCaptureSession|AVAudioSession|CLLocationManager|UNUserNotificationCenter|Battery|Brightness|Sensors|Accelerometer|Gyroscope|Magnetometer|Pedometer|Contacts|Calendar|LocalAuthentication|BiometricAuth|DocumentPicker|Print|ScreenOrientation|StatusBar|BackHandler|Appearance|Dimensions|PixelRatio|Keyboard|PushNotification|PushNotificationIOS|messaging|Bluetooth|BleManager|NfcManager|navigator\.\w+|window\.(?:open|print|alert|confirm|prompt)|Notification|speechSynthesis|WebAuthn|Intent|intent|context\.startActivity|startActivity|startService|sendBroadcast|registerReceiver|NotificationManager|notificationManager|NotificationCompat|LocationManager|locationManager|fusedLocationClient|SensorManager|sensorManager|CameraX|cameraProvider|MediaPlayer|mediaPlayer|AudioManager|audioManager|Vibrator|vibrator|ClipboardManager|clipboardManager|UIDevice|UIPasteboard|UIImpactFeedbackGenerator|UINotificationFeedbackGenerator|AVAudioPlayer|AVPlayer|CMMotionManager|PHPhotoLibrary|UIImagePickerController|LAContext|WKWebView|Process\.Start|Environment\.Exit|Clipboard\.\w+|Console\.\w+)\b"),

    # --------------------------------------------------------------- telemetry --
    _rule("telemetry",
          r"^(?:DdRum|DdLogs|DdTrace|DdSdkReactNative|CustomerIO|Sentry|Bugsnag|analytics|Analytics|crashlytics|Crashlytics|mixpanel|Mixpanel|amplitude|Amplitude|posthog|PostHog|LDClient|ldClient|Datadog|datadog|datadogRum|datadogLogs|newrelic|NewRelic|honeycomb|Honeycomb|segment|Segment|statsd|StatsD|metrics|Metrics|meter|Meter|meterRegistry|MeterRegistry|counter|histogram|tracer|Tracer|otel|opentelemetry|trace\.getTracer|span|Span|appInsights|TelemetryClient|_telemetryClient|telemetryClient|telemetry|_telemetry|Telemetry|Application\.Insights|logtail|Logtail|rollbar|Rollbar|raven|Raven|prometheus|Prometheus|promClient|prom|registry|Registry|sentry_sdk|capture_exception|capture_message|statsd_client|dogstatsd|MetricRegistry|Micrometer|Timer|Counter|Gauge|Histogram|Summary)\b(?:\.(?:\w+\.)*\w+)?$"),

    # ----------------------------------------------------------------- process --
    _rule("process", r"^(?:child_process|spawn|spawnSync|exec|execSync|execFile|execFileSync|fork|process\.exit|process\.kill|process\.abort|Deno\.(?:run|exit|Command|kill)|Bun\.(?:spawn|spawnSync|\$)|\$`|execa|execaSync|\$|zx|Worker|worker_threads|cluster\.fork|os\.setPriority|pm2\.\w+)$", ["js"]),
    _rule("process",
          r"^(?:subprocess\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput)|os\.(?:system|popen|execv|execve|execvp|execl|execlp|spawn\w*|fork|forkpty|kill|killpg|_exit|abort|nice|setsid|setuid|setgid|waitpid|wait)|sys\.exit|exit|quit|multiprocessing\.(?:Process|Pool)|Process|Pool|signal\.signal|signal\.alarm|pty\.spawn|asyncio\.create_subprocess_\w+|sh\.\w+|plumbum\.\w+|pexpect\.\w+|importlib\.import_module|__import__|ctypes\.\w+|cffi\.\w+)$", ["py"]),
    _rule("process",
          r"^(?:Runtime\.getRuntime\(\)\.exec|Runtime\.getRuntime\(\)\.halt|Runtime\.getRuntime|runtime\.exec|ProcessBuilder|System\.exit|System\.loadLibrary|System\.load|Thread\.sleep|Thread|Executors\.\w+|executor\.\w+|ForkJoinPool\.\w+|CompletableFuture\.\w+|Runtime\.exit|Runtime\.halt|exitProcess|ProcessHandle\.\w+|Signal\.\w+|thread|Timer|ScheduledExecutorService)(?:\.\w+)*$", ["jvm"]),
    _rule("process", r"^(?:Process\.(?:Start|Kill|GetProcesses\w*|GetCurrentProcess)|Environment\.(?:Exit|FailFast)|AppDomain\.\w+|Thread\.(?:Sleep|Start)|Task\.(?:Run|Factory\.StartNew|Delay)|ThreadPool\.\w+|Assembly\.(?:Load\w*)|Activator\.CreateInstance\w*|Marshal\.\w+|NativeLibrary\.\w+|ProcessStartInfo)$", ["cs"]),
    _rule("process", r"^(?:exec\.(?:Command|CommandContext|LookPath)|os\.(?:Exit|StartProcess|FindProcess|Getpid|Getenv|Setenv|Executable)|syscall\.\w+|signal\.(?:Notify|NotifyContext|Stop|Ignore|Reset)|log\.(?:Fatal\w*|Panic\w*)|runtime\.(?:GC|Goexit|GOMAXPROCS)|plugin\.Open|debug\.SetGCPercent|cmd\.(?:Run|Start|Output|CombinedOutput|Wait|Kill|StdoutPipe|StdinPipe|StderrPipe))$", ["go"]),
    _rule("process",
          r"^(?:fork|vfork|clone|execv|execve|execvp|execvpe|execl|execle|execlp|posix_spawn\w*|system|popen|pclose|waitpid|wait|wait3|wait4|waitid|kill|killpg|raise|signal|sigaction|sigprocmask|sigsuspend|sigwait|alarm|setitimer|pause|exit|_exit|_Exit|abort|atexit|quick_exit|setsid|setpgid|setpgrp|getpid|getppid|daemon|nice|setpriority|setrlimit|getrlimit|chroot|setuid|setgid|seteuid|setegid|setgroups|pthread_create|pthread_join|pthread_cancel|pthread_kill|pthread_detach|pthread_exit|thrd_create|thrd_join|dlopen|dlsym|dlclose|dlerror|LoadLibrary\w*|GetProcAddress|FreeLibrary|CreateProcess\w*|CreateThread|ExitProcess|ExitThread|TerminateProcess|TerminateThread|ShellExecute\w*|WinExec|WaitForSingleObject|WaitForMultipleObjects|sched_yield|sched_setaffinity|prctl|ptrace|uv_spawn|uv_process_kill|redisFork|bioCreateBackgroundJob|bioSubmitJob)$", ["c"]),
    _rule("process", r"^(?:system|spawn|exec|fork|Process\.\w+|Open3\.\w+|Kernel\.(?:system|spawn|exec|exit|exit!|abort|at_exit)|exit|exit!|abort|at_exit|Signal\.trap|trap|Thread\.new|Thread\.start|IO\.popen|PTY\.spawn|`)$", ["rb"]),
    _rule("process", r"^(?:exec|shell_exec|system|passthru|proc_open|popen|pcntl_\w+|posix_\w+|exit|die|Process::\w+|Artisan::\w+|new Process|Process)$", ["php"]),
    _rule("process", r"^(?:std::process|process|Command|std::thread|thread|tokio::spawn|tokio::process|spawn|rayon|libc)(?:::\w+)*$|^\w+\.(?:spawn|output|status|wait|kill)$", ["rs"]),
]

# ---------------------------------------------------------------------------
# receiver types
# ---------------------------------------------------------------------------

RECEIVER_TYPE_RULES: list[dict] = [
    {"category": "database", "pattern": _compile(r"(?:Repository|Repo|Dao|DAO|Mapper|EntityManager|DataSource|DbContext|DbSet|SessionFactory|JdbcTemplate|NamedParameterJdbcTemplate|MongoTemplate|MongoOperations|R2dbcEntityTemplate|DatabaseClient|PrismaClient|PrismaService|Knex|Kysely|Drizzle|Sequelize|ConnectionPool|MongoCollection|Datastore|IDbConnection|IRepository|IReadRepository|IUnitOfWork|UnitOfWork|DSLContext|EntityManagerFactory|SessionFactory|AsyncSession)(?:<[^>]*>)?$")},
    {"category": "network", "pattern": _compile(r"(?:HttpClient|RestTemplate|WebClient|RestClient|OkHttpClient|Retrofit|AxiosInstance|Axios|IHttpClientFactory|HttpClientFactory|GraphQLClient|GraphQlClient|WebSocketClient|StompSession|ManagedChannel|BlockingStub|AsyncStub|FeignClient|ApolloClient)(?:<[^>]*>)?$")},
    {"category": "auth", "pattern": _compile(r"(?:JwtService|JwtDecoder|JwtEncoder|PasswordEncoder|AuthenticationManager|UserManager|SignInManager|RoleManager|JwtSecurityTokenHandler|IPasswordHasher|PasswordHasher|KeycloakClient|OAuth2AuthorizedClientService)(?:<[^>]*>)?$")},
    {"category": "queue", "pattern": _compile(r"(?:Queue|IQueue|Producer|IProducer|Publisher|IPublisher|IPublishEndpoint|ISendEndpoint|IBus|IMessageBus|MessageBus|EventBus|IEventBus|Channel|KafkaTemplate|RabbitTemplate|JmsTemplate|StreamBridge|SqsClient|SnsClient|AmazonSQS|AmazonSNS|ApplicationEventPublisher|EventEmitter2|IBackgroundJobClient|BackgroundJobClient|Agenda|PgBoss)(?:<[^>]*>)?$")},
    {"category": "email", "pattern": _compile(r"(?:MailerService|JavaMailSender|MailSender|IEmailSender|SendGridClient|SESClient|AmazonSimpleEmailService|Transporter|Resend|PostmarkClient)(?:<[^>]*>)?$")},
    {"category": "payments", "pattern": _compile(r"(?:Stripe|StripeClient|BraintreeGateway|PayPalClient|Razorpay|Adyen|Mollie|Paddle|Chargebee)(?:<[^>]*>)?$")},
    {"category": "cache", "pattern": _compile(r"(?:CacheManager|IMemoryCache|IDistributedCache|RedisTemplate|StringRedisTemplate|Redis|RedisClient|Jedis|Lettuce|RedissonClient|MemcachedClient|IConnectionMultiplexer|ConnectionMultiplexer|IDatabase)(?:<[^>]*>)?$")},
    {"category": "storage", "pattern": _compile(r"(?:S3Client|AmazonS3|BlobClient|BlobServiceClient|BlobContainerClient|MinioClient|IFileProvider|Cloudinary|FileSystem|IFileSystem)(?:<[^>]*>)?$")},
]

# A plain instantiation of an exception the framework will turn into a
# response. Only in a project with endpoints: in an app, `new ValidationError`
# is an error, not a reply.
EXCEPTION_RESPONSE = _compile(
    r"(?:^|[.:\\])(?:\w+Exception|\w*HttpError|ApiError|\w+ApiError|HttpProblem|ProblemDetails|Abort|ResponseStatusException|ErrorResponse|\w+ErrorResponse|HTTPError|HTTPException|APIException|Http\d{3}|\w*(?:NotFound|BadRequest|Unauthorized|Unauthenticated|Forbidden|Conflict|Validation|Unprocessable|TooManyRequests|Gone|NotAllowed|MethodNotAllowed|Unsupported|RequestTimeout|InternalServer|ServiceUnavailable|PaymentRequired|PreconditionFailed|NotAcceptable|NotImplemented|BadGateway|RateLimit)Error)$")
NOT_A_RESPONSE = _compile(
    r"^(?:Error|TypeError|RangeError|SyntaxError|ReferenceError|EvalError|URIError|AggregateError|Exception|RuntimeException|IllegalArgumentException|IllegalStateException|NullPointerException|IndexOutOfBoundsException|UnsupportedOperationException|ArgumentException|ArgumentNullException|ArgumentOutOfRangeException|InvalidOperationException|NotImplementedException|NotSupportedException|ValueError|TypeError|KeyError|IndexError|RuntimeError|NotImplementedError|AssertionError|StopIteration|InterruptedException|IOException|FileNotFoundException|ClassNotFoundException|NoSuchElementException|NumberFormatException|CloneNotSupportedException|ExecutionException|TimeoutException|OperationCanceledException|TaskCanceledException|ObjectDisposedException|FormatException|OverflowException|DivideByZeroException|JsonException|SerializationException|ParseException|DateTimeParseException|MalformedURLException|URISyntaxException|SQLException|DataAccessException|DbUpdateException|ConcurrencyException|EntityNotFoundException|NoResultException|OptimisticLockException|InvalidArgumentException|LogicException|DomainException|LengthException|OutOfRangeException|OutOfBoundsException|UnexpectedValueException|BadMethodCallException|BadFunctionCallException|RangeException|UnderflowException|ErrorException|JsonException|TypeError)$")

# Swift names the table knows from other stacks: Foundation's `Timer`
# schedules work (Micrometer's is telemetry), `Calendar` does date math
# (expo-calendar's is the device), and an `intent` is SiriKit configuration.
SWIFT_NOT_AN_EFFECT = _compile(r"^(?:Timer|Calendar|Intent|intent)\b")

READ_OPS = _compile(
    r"^(?:find\w*|findone|get|getone|getmany|getall\w*|getbyid\w*|getasync|list\w*|count\w*|aggregate|select\w*|query\w*|queryrow\w*|scalar\w*|first\w*|single\w*|last\w*|all|any\w*|exists\w*|tolist\w*|toarray\w*|filter|where|fetch\w*|load\w*|read\w*|scan|search|paginate|pluck|distinct|group\w*|order\w*|include\w*|join\w*|objects|values|values_list|iterator|stream|max|min|sum|avg|average|exists\?|one|one_or_none|scalars?|find_by|find_each|firstordefault\w*|singleordefault\w*|countdocuments|rows|row|preload|take|limit|offset|skip|raw|fromsql\w*|\$queryraw|get_or_404|get_object_or_404|describe\w*|head\w*|retrieve|show|index|lookup|peek|contains|has|check|isempty|is_empty|size|length|fetchone|fetchall|fetchmany|refresh)$",
    re.IGNORECASE)
WRITE_OPS = _compile(
    r"^(?:create\w*|update\w*|upsert\w*|delete\w*|destroy\w*|save\w*|insert\w*|remove\w*|add\w*|persist\w*|merge|flush|commit|bulk\w*|batch\w*|put\w*|set\w*|exec|execute\w*|savechanges\w*|increment\w*|decrement\w*|truncate|drop|sqlmodel_update|find_or_create\w*|update_or_create|firstorcreate|updateorcreate|get_or_create|delete_all|update_all|insert_all|upsert_all|refresh_from_db|patch|write\w*|push|pull|inc|attach|detach|sync|replace\w*|touch|purge|restore|forcedelete|store|migrate|automigrate|createmany|updatemany|deletemany|\$executeraw|\$transaction|transaction|begin|rollback|expunge|lock|unlock|import|reindex|rebuild|clear|reset|empty|fill|assign|append|prepend|move|copy|rename|link|unlink|register|unregister|enable|disable|activate|deactivate|approve|reject|publish|unpublish|archive|unarchive|complete|cancel|confirm|revoke|grant|deny|ban|unban|verify|invalidate|expire|evict|generate|seed)$",
    re.IGNORECASE)

MODEL_SUFFIX = _compile(r"(?:Repository|Repo|Dao|DAO|Model|Mapper|Store|Collection|Table|Service|Entity|Manager)$")


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------



def normalise_call(text: str) -> str:
    """The text the rules see: ``await``/``new`` dropped, ``?.`` as ``.``.

    Faithful port of ``normaliseCall`` from effects.ts. ``this.`` is kept: a
    rule that matches ``this.jwtService.sign`` must still see it.
    """
    out = str(text or "")
    for _ in range(2):  # the TS runs the same replace twice
        stripped = re.sub(r"^\s*(?:await|new|yield|return|throw)\s+", "", out, count=1)
        if stripped == out:
            break
        out = stripped
    out = out.replace("?.", ".").replace("!.", ".")
    out = re.sub(r"\s+", "", out)
    out = re.sub(r"<[^<>]*>", "", out)
    return out


def _families_of(language: str | None) -> list[str]:
    """The rule-family names a CodeGraph language belongs to (possibly none)."""
    if not language:
        return []
    lang = str(language)
    return [family for family, langs in FAMILIES.items() if lang in langs]


def _strip_call_args(text: str) -> str:
    """Drop innermost argument lists, one pass — the same single JS pass."""
    return re.sub(r"\([^()]*\)", "", text)


def _model_of(segments: list[str], args: str | None, receiver_type: str | None) -> str | None:
    """Best-effort model name for a database call's chain/receiver, or None."""
    no_this = segments[1:] if segments and segments[0] in ("this", "self") else segments
    first = no_this[0] if no_this else ""
    second_last = no_this[-2] if len(no_this) >= 3 else ""
    if (len(no_this) >= 3 and re.fullmatch(r"[A-Za-z_$][\w$]*", second_last)
            and not re.fullmatch(r"(?:objects|query|session|db|\$|from|table|collection|opsForValue|Items)", second_last)
            and not MODEL_SUFFIX.search(second_last) and second_last != "$transaction"):
        if re.fullmatch(r"(?:prisma|db|database|orm|em|drizzle|sql|_context|context|dbContext|_db|ctx|this)", first, re.IGNORECASE) \
                or re.search(r"(?:Context|Client|Prisma|Db|DB)$", first):
            return second_last
    receiver = no_this[0] if len(no_this) >= 2 else ""
    if receiver and MODEL_SUFFIX.search(receiver) and receiver not in ("this", "self"):
        stem = re.sub(r"^_+", "", receiver)
        stem = MODEL_SUFFIX.sub("", stem)
        if stem:
            return stem
    if len(no_this) >= 2 and re.fullmatch(r"[A-Z][A-Za-z0-9]*", first) and first not in ("DB", "ActiveRecord", "Files", "File", "Path", "Base"):
        return first
    if receiver_type:
        stem = re.sub(r"<[^>]*>", "", receiver_type)
        stem = re.sub(r"^I(?=[A-Z])", "", stem)
        stem = MODEL_SUFFIX.sub("", stem)
        if stem and stem != receiver_type and re.match(r"^[A-Z]", stem) \
                and not re.match(r"^(?:Entity|Db|Data|Jdbc|Mongo|Session|Async)$", stem):
            return stem
    if args:
        last = no_this[-1] if no_this else ""
        if re.fullmatch(r"(?:knex|db|collection|table|from|into|selectFrom|insertInto|updateTable|deleteFrom|sql\.table|query|getRepository|getCollection|model)", last, re.IGNORECASE):
            m = re.match(r"^['\"`]([\w.-]+)['\"`]", args)
            if m:
                return m.group(1)
    return None


def _with_shape(category: str, text: str, args: str | None, language: str | None,
                receiver_type: str | None) -> dict:
    """Add database model/access fields; other categories retain their label."""
    if category != "database":
        return {"category": category}
    out: dict = {"category": category}
    segments = [s for s in re.split(r"[.:]+", _strip_call_args(text)) if s]
    last = segments[-1] if segments else ""
    model = _model_of(segments, args, receiver_type)
    if model:
        out["model"] = model
    op = re.sub(r"[!?]$", "", last)
    if op == "exec" and language == "python":
        out["access"] = "read"
    elif WRITE_OPS.search(op):
        out["access"] = "write"
    elif READ_OPS.search(op):
        out["access"] = "read"
    return out


def classify_effect(text: str, language: str | None = None, kind: str = "calls",
                    receiver_type: str | None = None, project: str = "app",
                    args: str | None = None) -> dict | None:
    """What a call is, when the table names it. None for everything else.

    Port of ``classifyEffect``. Returns ``{"category", "model"?, "access"?}``
    (``model``/``access`` only for ``database``); :func:`classify_call` wraps it
    for callers that only want the category strings.
    """
    normalised = normalise_call(text)
    chain = _strip_call_args(normalised)
    if chain == "":
        return None
    families = _families_of(language)
    if "swift" in families and SWIFT_NOT_AN_EFFECT.search(chain):
        return None
    for rule in EFFECT_RULES:
        if rule["only"] and not (rule["only"] & set(families)):
            # An ungated language (no family) still gets the JS rows — the table
            # grew up on them, and language can be unknown at the call site.
            if language:
                continue
            if "js" not in rule["only"]:
                continue
        if rule["instantiates"] and kind != "instantiates":
            continue
        if rule["pattern"].search(chain):
            return _with_shape(rule["category"], chain, args, language, None)
    if receiver_type:
        cleaned = re.sub(r"^(?:readonly|private|public|protected|final|static)\s+", "", str(receiver_type)).strip()
        for rule in RECEIVER_TYPE_RULES:
            if rule["pattern"].search(cleaned):
                return _with_shape(rule["category"], chain, args, language, cleaned)
    if project != "app" and (kind == "instantiates" or "py" in families or "swift" in families):
        last = re.split(r"[.:]", chain)[-1]
        last = re.sub(r"^.*\\", "", last)
        if EXCEPTION_RESPONSE.search(chain) and not NOT_A_RESPONSE.search(last):
            return {"category": "response"}
    return None


def classify_call(text: str, language: str | None = None, kind: str = "calls",
                  receiver_type: str | None = None, project: str = "app",
                  args: str | None = None, tail_fallback: bool = True) -> list[str]:
    """The effect categories of a call — usually exactly one, never more.

    ``text`` is the call as written (``db.query``, ``res.status(404).json``,
    ``this.jwtService.signAsync``); ``language`` is a CodeGraph
    ``nodes.language`` value (``python``, ``typescript``, ``csharp`` …) which
    gates the family-specific rows. An empty list means "not an effect" — a
    plain call into a library is not a sink.

    The one SAST-side addition to the faithful table: ``tail_fallback``. The
    TypeScript module documents that "the index keeps only the last segment of
    a deep chain", so its rows are deliberately written for bare names too
    (``spawn``, ``exit``, ``fork`` are rules on their own). When a whole-chain
    match fails — ``child_process.exec`` is anchored to ``child_process`` and
    so matches nothing — the last segment is retried, which is exactly the text
    a graph-sourced reference gives you. Pass ``tail_fallback=False`` for strict
    TypeScript parity. It over-reports a rare member call
    (``x.exec`` -> process) and never under-reports one, which is the right
    direction for sink discovery: a caller that wants precision re-reads the
    line before claiming anything.
    """
    effect = classify_effect(text, language, kind, receiver_type, project, args)
    if effect is None and tail_fallback:
        chain = normalise_call(text)
        chain = _strip_call_args(chain)
        segments = [s for s in chain.split(".") if s]
        if len(segments) >= 2:
            effect = classify_effect(segments[-1], language, kind,
                                     receiver_type, project, args)
    return [effect["category"]] if effect else []
