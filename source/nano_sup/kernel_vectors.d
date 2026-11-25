/// Golden vectors for the generated kernel. A wrong transition fails `dub test`.
module nano_sup.kernel_vectors;

@safe:

import nano_sup.kernel;

private Slot drive(bool nested, const(Event)[] evs) pure nothrow @nogc
{
    auto s = Slot(nested);
    foreach (e; evs)
        assert(step(s, e) == Err.Ok);
    return s;
}

@("happy path: empty -> starting -> leased -> running -> draining -> dead")
unittest
{
    auto s = Slot(false);
    assert(step(s, Event.Start) == Err.Ok && s.state == State.Starting);
    assert(step(s, Event.Lease) == Err.Ok && s.state == State.Leased && s.leaseHeld);
    assert(step(s, Event.Run) == Err.Ok && s.state == State.Running && s.inFlight == 1);
    assert(step(s, Event.Complete) == Err.Ok && s.state == State.Starting);
    assert(!s.leaseHeld && s.inFlight == 0);
    assert(step(s, Event.Drain) == Err.Ok && s.state == State.Draining);
    assert(step(s, Event.ExecSuccessor) == Err.Ok && s.state == State.Dead);
}

@("golden: complete after lost lease is illegal and does not settle")
unittest
{
    auto s = drive(false, [Event.Start, Event.Lease, Event.Run, Event.LeaseLost]);
    const before = s;
    assert(step(s, Event.Complete) == Err.LeaseNotHeld);
    assert(step(s, Event.Fail) == Err.LeaseNotHeld);
    assert(s == before && s.inFlight == 1);
    assert(step(s, Event.Abandon) == Err.Ok && s.state == State.Starting && s.inFlight == 0);
}

@("golden: upgrade while in flight is refused")
unittest
{
    auto s = drive(false, [Event.Start, Event.Lease, Event.Run, Event.Drain]);
    assert(s.state == State.Draining && s.inFlight == 1);
    assert(step(s, Event.ExecSuccessor) == Err.InFlight);
    assert(s.state == State.Draining);
    assert(step(s, Event.Complete) == Err.Ok && s.state == State.Draining);
    assert(step(s, Event.ExecSuccessor) == Err.Ok && s.state == State.Dead);
}

@("golden: upgrade only from draining")
unittest
{
    auto s = drive(false, [Event.Start]);
    assert(step(s, Event.ExecSuccessor) == Err.Illegal);
}

@("golden: start while nested is forbidden")
unittest
{
    auto s = Slot(true);
    assert(step(s, Event.Start) == Err.NestedForbidden);
    assert(s.state == State.Empty);
}

@("pin is write-once")
unittest
{
    auto s = Slot(false);
    assert(step(s, Event.Pin) == Err.Ok && s.pinned);
    assert(step(s, Event.Pin) == Err.AlreadyPinned);
}

@("drain and force are distinct")
unittest
{
    auto d = drive(false, [Event.Start, Event.Lease, Event.Run, Event.Drain]);
    assert(d.state == State.Draining && d.leaseHeld);
    auto f = drive(false, [Event.Start, Event.Lease, Event.Run, Event.Force]);
    assert(f.state == State.Dead && !f.leaseHeld && f.inFlight == 0);
    assert(step(f, Event.Drain) == Err.Illegal);
    assert(step(f, Event.Force) == Err.Illegal);
}

@("dead is terminal")
unittest
{
    auto s = drive(false, [Event.Force]);
    foreach (e; [Event.Start, Event.Pin, Event.Lease, Event.Run, Event.Complete,
            Event.Fail, Event.LeaseLost, Event.Abandon, Event.Drain, Event.Force,
            Event.ExecSuccessor])
        assert(step(s, e) == Err.Illegal);
}

@("slot state is not writable outside the kernel")
unittest
{
    auto s = Slot(false);
    static assert(!__traits(compiles, s.state_ = State.Running));
    static assert(!__traits(compiles, s.state = State.Running));
}

@("golden: exec-successor refuses while the lease is still held")
unittest
{
    auto s = drive(false, [Event.Start, Event.Lease, Event.Drain]);
    const before = s;
    assert(step(s, Event.ExecSuccessor) == Err.LeaseStillHeld);
    assert(s == before && s.state == State.Draining && s.leaseHeld);
}

@("golden: exec-successor after lease lost reaches dead without a lease")
unittest
{
    auto s = drive(false, [Event.Start, Event.Lease, Event.Drain, Event.LeaseLost]);
    assert(step(s, Event.ExecSuccessor) == Err.Ok);
    assert(s.state == State.Dead && !s.leaseHeld && s.inFlight == 0);
}

@("golden: force from draining with a lease reaches dead without a lease")
unittest
{
    auto s = drive(false, [Event.Start, Event.Lease, Event.Drain, Event.Force]);
    assert(s.state == State.Dead && !s.leaseHeld && s.inFlight == 0);
}
