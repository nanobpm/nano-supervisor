/// Stub binary: exercises the generated kernel seam. Not the product (Rust `main` is).
module app;

@safe:

import nano_sup.kernel;

int main()
{
    import std.stdio : writeln;

    auto s = Slot(false);
    foreach (e; [Event.Start, Event.Lease, Event.Run, Event.Complete, Event.Drain,
            Event.ExecSuccessor])
    {
        const r = step(s, e);
        writeln(e, " -> ", s.state, " (", r, ")");
        if (r != Err.Ok)
            return 1;
    }
    return 0;
}
