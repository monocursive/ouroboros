def sum_even(numbers):
    return sum(n for n in numbers if isinstance(n, int) and not isinstance(n, bool) and n % 2 == 0)
