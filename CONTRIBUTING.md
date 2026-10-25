# Contributing to REO

Thank you for your interest in improving **REO (Reverse Engineering Orchestrator)**!

## Development Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/abeeropu/reo.git
   cd reo
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Build TypeScript**:
   ```bash
   npm run build
   ```

4. **Run Tests**:
   ```bash
   npm test
   ```

5. **Run CLI in development**:
   ```bash
   npm run dev -- doctor
   ```

## Pull Request Guidelines

- Ensure `npm run build` and `npm test` pass with zero errors.
- Follow modern TypeScript standards with strict type checking.
- Document any new features or engine connectors in `ARCHITECTURE.md`.
