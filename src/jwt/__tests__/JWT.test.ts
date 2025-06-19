import { expect, test} from 'vitest';
import { JWT } from '../JWT';
import { Factory, CryptoKey } from '@muisit/cryptokey';

test('create JWT', async () => {
    const jwt = new JWT();
    jwt.header = {typ: 'JWT', alg: 'EdDSA'};
    jwt.payload = { claim: "something"};

    const key = await Factory.createFromType('Ed25519');
    key.initialisePrivateKey(
        CryptoKey.hexToBytes(
          "fbe04e71bce89f37e0970de16a97a80c4457250c6fe0b1e9297e6df778ae72a8",
        ),
    );
    await jwt.sign(key);

    expect(jwt.headerPart).toBeDefined();
    expect(jwt.headerPart).toBe('eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6IjVjMzE5YjhjMmQ0ODAzMjAyNjczZWQxYWIyNGJkMzQyNWI5MTRkNDI0ODE5NjdhYzRjZDkzY2NmYzdkZWNiMzkifQ');
    expect(jwt.payloadPart).toBeDefined();
    expect(jwt.payloadPart).toBe('eyJjbGFpbSI6InNvbWV0aGluZyJ9');
    expect(jwt.signaturePart).toBeDefined();
    expect(jwt.signaturePart).toBe('jgHna2E5bzTLOGAux4znzPFy926jhgkoGilambOalqBSBrgpa9STbbCG7ef2IfydLuNzH6kSCI3bNjzOLs8aBg');
    expect(jwt.token).toBeDefined();
    expect(jwt.token).toBe('eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6IjVjMzE5YjhjMmQ0ODAzMjAyNjczZWQxYWIyNGJkMzQyNWI5MTRkNDI0ODE5NjdhYzRjZDkzY2NmYzdkZWNiMzkifQ.eyJjbGFpbSI6InNvbWV0aGluZyJ9.jgHna2E5bzTLOGAux4znzPFy926jhgkoGilambOalqBSBrgpa9STbbCG7ef2IfydLuNzH6kSCI3bNjzOLs8aBg');
});


test('sign with Function', async () => {
    const jwt = new JWT();
    jwt.header = {typ: 'JWT', alg: 'EdDSA'};
    jwt.payload = { claim: "something"};

    const key = await Factory.createFromType('Ed25519');
    key.initialisePrivateKey(
        CryptoKey.hexToBytes(
          "fbe04e71bce89f37e0970de16a97a80c4457250c6fe0b1e9297e6df778ae72a8",
        ),
    );
    await jwt.sign((data:Uint8Array) => key.sign("EdDSA", data, 'base64url'));

    // the header does not contain kid now
    expect(jwt.headerPart).toBeDefined();
    expect(jwt.headerPart).toBe('eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9');
    expect(jwt.payloadPart).toBeDefined();
    expect(jwt.payloadPart).toBe('eyJjbGFpbSI6InNvbWV0aGluZyJ9');
    expect(jwt.signaturePart).toBeDefined();
    expect(jwt.signaturePart).toBe('LXlbxK-IrpDrS9eKECt50QUK7d4QUWvq__NeW1DRBVIzCjyoIR1guPeaa-0NAo529ZNy8sXnD8nrEHsX3sg8DA');
    expect(jwt.token).toBeDefined();
    expect(jwt.token).toBe('eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJjbGFpbSI6InNvbWV0aGluZyJ9.LXlbxK-IrpDrS9eKECt50QUK7d4QUWvq__NeW1DRBVIzCjyoIR1guPeaa-0NAo529ZNy8sXnD8nrEHsX3sg8DA');
});

test('verify JWT', async () => {
    const key = await Factory.createFromType('Ed25519');
    key.initialisePrivateKey(
        CryptoKey.hexToBytes(
          "fbe04e71bce89f37e0970de16a97a80c4457250c6fe0b1e9297e6df778ae72a8",
        ),
    );
    const token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6IjVjMzE5YjhjMmQ0ODAzMjAyNjczZWQxYWIyNGJkMzQyNWI5MTRkNDI0ODE5NjdhYzRjZDkzY2NmYzdkZWNiMzkifQ.eyJjbGFpbSI6InNvbWV0aGluZyJ9.jgHna2E5bzTLOGAux4znzPFy926jhgkoGilambOalqBSBrgpa9STbbCG7ef2IfydLuNzH6kSCI3bNjzOLs8aBg';
    const jwt = JWT.fromToken(token);
    const result = await jwt.verify(key);
    expect(result).toBeTruthy();
});

test('verify JWT(2)', async () => {
    const key = await Factory.createFromType('Ed25519');
    key.initialisePrivateKey(
        CryptoKey.hexToBytes(
          "fbe04e71bce89f37e0970de16a97a80c4457250c6fe0b1e9297e6df778ae72a8",
        ),
    );
    const token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJjbGFpbSI6InNvbWV0aGluZyJ9.LXlbxK-IrpDrS9eKECt50QUK7d4QUWvq__NeW1DRBVIzCjyoIR1guPeaa-0NAo529ZNy8sXnD8nrEHsX3sg8DA';
    const jwt = JWT.fromToken(token);
    const result = await jwt.verify(key);
    expect(result).toBeTruthy();
});

test('fail JWT verify:wrong key', async () => {
    const key = await Factory.createFromType('Ed25519');
    key.initialisePrivateKey(
        CryptoKey.hexToBytes(
          "fbe04e71bce89f37e0970de16a97a80c4457250c6fe0b1e9297e6df778ae72a9", // wrong key
        ),
    );
    const token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6IjVjMzE5YjhjMmQ0ODAzMjAyNjczZWQxYWIyNGJkMzQyNWI5MTRkNDI0ODE5NjdhYzRjZDkzY2NmYzdkZWNiMzkifQ.eyJjbGFpbSI6InNvbWV0aGluZyJ9.jgHna2E5bzTLOGAux4znzPFy926jhgkoGilambOalqBSBrgpa9STbbCG7ef2IfydLuNzH6kSCI3bNjzOLs8aBg';
    const jwt = JWT.fromToken(token);
    const result = await jwt.verify(key);
    expect(result).toBeFalsy();
});

test('fail JWT verify:wrong payload', async () => {
    const key = await Factory.createFromType('Ed25519');
    key.initialisePrivateKey(
        CryptoKey.hexToBytes(
          "fbe04e71bce89f37e0970de16a97a80c4457250c6fe0b1e9297e6df778ae72a8",
        ),
    );
    // payload adjusted
    const token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6IjVjMzE5YjhjMmQ0ODAzMjAyNjczZWQxYWIyNGJkMzQyNWI5MTRkNDI0ODE5NjdhYzRjZDkzY2NmYzdkZWNiMzkifQ.eyJjbGFpbSI6InNvbWV0aGluZyBlbHNlIn0.jgHna2E5bzTLOGAux4znzPFy926jhgkoGilambOalqBSBrgpa9STbbCG7ef2IfydLuNzH6kSCI3bNjzOLs8aBg';
    const jwt = JWT.fromToken(token);
    const result = await jwt.verify(key);
    expect(result).toBeFalsy();
});

test('fail JWT verify:wrong payload', async () => {
    const key = await Factory.createFromType('Ed25519');
    key.initialisePrivateKey(
        CryptoKey.hexToBytes(
          "fbe04e71bce89f37e0970de16a97a80c4457250c6fe0b1e9297e6df778ae72a8",
        ),
    );
    // signature adjusted
    const token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6IjVjMzE5YjhjMmQ0ODAzMjAyNjczZWQxYWIyNGJkMzQyNWI5MTRkNDI0ODE5NjdhYzRjZDkzY2NmYzdkZWNiMzkifQ.eyJjbGFpbSI6InNvbWV0aGluZyJ9.jgHna2E5bzTLOGAux4znzPFy926jhgkoGilambOalqBSBrgpa9STbbCG7ef2IfydLuNzH6kSCI3bNjzOLs8bBg';
    const jwt = JWT.fromToken(token);
    const result = await jwt.verify(key);
    expect(result).toBeFalsy();
});

test('fail invalid JSON in header', () => {
    const token = 'WyJjbGFpbSI6InNvbWV0aGluZyJ9.eyJjbGFpbSI6InNvbWV0aGluZyJ9.jgHna2E5bzTLOGAux4znzPFy926jhgkoGilambOalqBSBrgpa9STbbCG7ef2IfydLuNzH6kSCI3bNjzOLs8bBg';
    expect(() => JWT.fromToken(token)).toThrow("Invalid JWT");
});

test('fail invalid JSON in payload', () => {
    const token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6IjVjMzE5YjhjMmQ0ODAzMjAyNjczZWQxYWIyNGJkMzQyNWI5MTRkNDI0ODE5NjdhYzRjZDkzY2NmYzdkZWNiMzkifQ.WyJjbGFpbSI6InNvbWV0aGluZyJ9.eyJjbGFpbSI6InNvbWV0aGluZyJ9.jgHna2E5bzTLOGAux4znzPFy926jhgkoGilambOalqBSBrgpa9STbbCG7ef2IfydLuNzH6kSCI3bNjzOLs8bBg';
    expect(() => JWT.fromToken(token)).toThrow("Invalid JWT");
});

test('fail missing header', () => {
    const token = '.jgHna2E5bzTLOGAux4znzPFy926jhgkoGilambOalqBSBrgpa9STbbCG7ef2IfydLuNzH6kSCI3bNjzOLs8bBg';
    expect(() => JWT.fromToken(token)).toThrow("Invalid JWT");
});

test('fail missing payload', () => {
    const token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6IjVjMzE5YjhjMmQ0ODAzMjAyNjczZWQxYWIyNGJkMzQyNWI5MTRkNDI0ODE5NjdhYzRjZDkzY2NmYzdkZWNiMzkifQ..jgHna2E5bzTLOGAux4znzPFy926jhgkoGilambOalqBSBrgpa9STbbCG7ef2IfydLuNzH6kSCI3bNjzOLs8bBg';
    expect(() => JWT.fromToken(token)).toThrow("Invalid JWT");
});

test('fail missing signature', () => {
    const token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6IjVjMzE5YjhjMmQ0ODAzMjAyNjczZWQxYWIyNGJkMzQyNWI5MTRkNDI0ODE5NjdhYzRjZDkzY2NmYzdkZWNiMzkifQ.eyJjbGFpbSI6InNvbWV0aGluZyJ9.';
    expect(() => JWT.fromToken(token)).toThrow("Invalid JWT");
});

test('fail too many parts', () => {
    const token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6IjVjMzE5YjhjMmQ0ODAzMjAyNjczZWQxYWIyNGJkMzQyNWI5MTRkNDI0ODE5NjdhYzRjZDkzY2NmYzdkZWNiMzkifQ.eyJjbGFpbSI6InNvbWV0aGluZyJ9.jgHna2E5bzTLOGAux4znzPFy926jhgkoGilambOalqBSBrgpa9STbbCG7ef2IfydLuNzH6kSCI3bNjzOLs8bBg.extra';
    expect(() => JWT.fromToken(token)).toThrow("Invalid JWT");
});

test('fail too few parts', () => {
    const token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6IjVjMzE5YjhjMmQ0ODAzMjAyNjczZWQxYWIyNGJkMzQyNWI5MTRkNDI0ODE5NjdhYzRjZDkzY2NmYzdkZWNiMzkifQ.eyJjbGFpbSI6InNvbWV0aGluZyJ9';
    expect(() => JWT.fromToken(token)).toThrow("Invalid JWT");
});