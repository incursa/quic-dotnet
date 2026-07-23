// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Internal campaign identities for application-send turn planning.
/// </summary>
/// <remarks>
/// These identities are intentionally internal. Both currently retain the
/// established priority-and-sequence selector; <see cref="Conservative"/>
/// makes that selector explicit so a campaign can prove the force seam without
/// introducing an alternate scheduler or weakening runtime guards.
/// </remarks>
internal enum QuicApplicationSendTurnPolicyMode
{
    LegacyCurrent = 0,
    Conservative = 1,
}
