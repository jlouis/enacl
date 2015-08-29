/* Dirty NIF schedule overhead */
pid$target:beam.smp:schedule_dirty_cpu_nif:return
{
	s = timestamp;
}

pid$target:libsodium.so.*:randombytes:entry {
	e = timestamp;
}

pid$target:beam.smp:execute_dirty_nif:entry
/s != 0/
{
	@SchedTime = lquantize(timestamp - s, 0, 10000, 250);
	s = 0;
}

pid$target:beam.smp:execute_dirty_nif:return
{
	@ExecTime = lquantize(timestamp - e, 0, 10000, 250);
	e = 0;
	r = timestamp;
}

pid$target:beam.smp:dirty_nif_finalizer:entry
/r != 0/
{
	@ReturnTime = lquantize(timestamp - r, 0, 10000, 250);
	r = 0;
}

END
{
	printa("Scheduling overhead (nanos):%@d\n", @SchedTime);
	printa("Return overhead (nanos):%@d\n", @ReturnTime);
	printa("Exec time (nanos):%@d\n", @ExecTime);
}
